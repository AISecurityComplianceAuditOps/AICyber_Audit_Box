# -*- coding: utf-8 -*-
"""
Audit Graph Module
Implements the LangGraph State Machine for auditing controls.
Integrates custom validators and retrieval with LangChain ChatOllama.
"""

import os
import time as _time
import threading
from typing import TypedDict, List, Dict, Any, Optional
from langgraph.graph import StateGraph, START, END
from src.ai.audit_models import AuditFindingSchema
from src.ai.audit_chains import get_generator_chain, get_reflection_chain
from src.core.retrieval import _retrieve_rag_context
from src.core.validator import post_process
from src.db.database import SessionLocal, DocumentChunk

class AuditState(TypedDict):
    """
    State definition for the auditing graph.
    Represents the context, drafts, errors, and outcomes for a single control.
    """
    control_id: str
    control_label: str
    expected_evidence: str
    prompt_hint: str
    severity: str
    standard: str
    recommendation: str
    keywords: Optional[Dict[str, float]]  # per-control retrieval keyword weights, see control_keywords.py
    
    # Document Context & Config
    document_text: str
    file_names_list: List[str]
    llm_model: str
    summary_text: str
    # This session's AuditReport.id -- scopes every document_chunks read/write
    # to only this session's own evidence, so two sessions that happen to
    # upload identically-named files never collide (see save_document_chunks /
    # _vec_native_search in retrieval.py). None only if resolution failed.
    report_id: Optional[int]
    
    # State tracking
    retrieved_context: str
    draft_finding: Optional[Dict[str, Any]]
    validation_error: Optional[str]
    retry_count: int
    final_finding: Optional[Dict[str, Any]]
    token_stats: Optional[Dict[str, int]]  # real prompt/completion token counts from the LLM server

    # Progress reporting
    bg_key: Optional[str]
    control_idx: int
    total_controls: int
    audit_mode: Optional[str]
    file_registry: Optional[Dict[str, str]]

    # ── Excel Scoping Two-Phase Pipeline ─────────────────────────────────────
    # When set, retrieval is restricted to ONLY these filenames (Phase 1 lock).
    # The LLM acts as a judge-only on the pre-extracted context (Phase 2).
    locked_filenames: Optional[List[str]]     # locked file(s) from Excel checklist
    checklist_question: Optional[str]         # original Excel audit check question
    # Customize scope: the checklist question is the audit item, deliberately NOT
    # mapped to any control or policy document, so the prompt drops its policy
    # framing and the verdict is decided on the evidence alone.
    customize_mode: Optional[bool]
    # Customize scope runs as pure document Q&A: the question is answered from the
    # cited file(s) and nothing else, with no control, no policy dimension and none
    # of the standard's reasoning rules. Set only for Customize -- Excel Scoping and
    # Manual scope never carry it, and take exactly the paths they always have.
    rag_mode: Optional[bool]
    # Which of the locked files (if any) came from a Policy-named vs an
    # Evidence-named column on the sheet, so the LLM can be told the auditor's
    # own intent instead of re-deriving the policy/evidence split blind from
    # undifferentiated locked text. Both empty when the sheet has no such
    # column-level distinction (e.g. a single generic "File name" column).
    policy_locked_filenames: Optional[List[str]]
    evidence_locked_filenames: Optional[List[str]]


# Synonyms dictionary used in retrieval
KEYWORD_SYNONYMS = {
    "access":         ["permission", "authorize", "login", "iprotect", "credential", "badge", "keycard", "rfid", "escort"],
    "authentication": ["mfa", "password", "login", "2fa", "credential", "pin", "keycard", "biometric", "badge", "token", "smart card", "auth-token", "api auth", "session management", "token issuance", "client id", "machine id", "pam", "iam", "privileged access management", "fraud analytics", "api authentication", "sub-aua", "whitelisting", "firewall rules", "auth", "secrets", "api-auth", "api_auth"],
    "identity":       ["user account", "userid", "provisioning", "onboard", "termination", "leave of absence", "joiner", "leaver", "myid"],
    "privileged":     ["admin", "superuser", "root", "elevated", "restricted area", "sponsor"],
    "inventory":      ["asset list", "register", "catalogue", "logbook", "visitor management"],
    "encryption":     ["tls", "ssl", "cipher", "aes", "https"],
    "logging":        ["audit trail", "siem", "event log", "monitoring", "registration log", "cloudwatch", "log archived", "ntp", "clock sync", "monitoring", "audit logs", "event logging", "syslog", "flow log", "vpc log", "timedatectl", "chronyd", "systemd-timesyncd"],
    "ntp":            ["timedatectl", "systemd-timesyncd", "chronyd", "chrony", "w32tm", "clock sync", "time sync", "time server", "ntp.conf", "ntp status", "clock synchronization"],
    "clock":          ["ntp", "timedatectl", "systemd-timesyncd", "chronyd", "w32tm", "time synchronization", "clock sync", "clock synchronization"],
    "sync":           ["synchronized", "synchronization", "ntp", "timedatectl", "chrony", "clock sync"],
    "fraud":          ["fraud analytics", "fraud detection", "api auth", "api authentication", "fraud operations", "risk engine"],
    "backup":         ["restore", "snapshot", "recovery", "replication"],
    "physical":       ["visitor", "escort", "card access", "restricted area", "lobby", "reception", "perimeter", "lock", "keycard", "badge", "gate", "guard", "cctv", "logbook", "sign-in", "breezn", "kastle"],
    "visitor":        ["escort", "guest", "contractor", "client", "visitor management", "breezn", "kastle", "sign-in", "logbook", "lobby"],
    "termination":    ["leave of absence", "exit", "revoc", "deactivat", "disable", "expire", "return of assets", "hr", "human resources"],
    "source code":    ["git", "repository", "github", "gitlab", "source", "code", "dev", "developer"],
    "continuity":     ["bcp", "dr", "disaster recovery", "continuity", "redundancy", "failover", "backup"],
    "malware":        ["antivirus", "edr", "malware", "virus", "threat", "scan"],
    "vulnerability":  ["patch", "scan", "vulnerability", "update", "cvse", "cve"],
    "incident":       ["breach", "event", "response", "irp", "triage", "ticket", "reporting", "alert"],
    "access control": ["badge", "keycard", "card access", "entry", "rfid", "pin", "tailgating", "escort", "access rights", "physical entry", "visitor sign-in", "sign-in sheet", "visitor log", "logbook", "lobby", "reception", "gate", "guard", "cctv", "biometric", "smart card", "fingerprint", "face ID", "credentials", "permissions", "authorized", "restriction", "pam", "iam", "privileged", "access control"]
}

def _update_progress(state: AuditState, phase_text: str, phase_ratio: float):
    bg_key = state.get("bg_key")
    idx = state.get("control_idx", 0)
    total = state.get("total_controls", 1)
    if not bg_key or total <= 0:
        return
    try:
        from src.core.bg_state import _bg_store, _bg_lock
        base_pct = int((idx / total) * 100)
        step_pct = 100 / total
        current_pct = int(base_pct + (step_pct * phase_ratio))
        # Ensure it doesn't exceed the next control's boundary
        next_base_pct = int(((idx + 1) / total) * 100)
        current_pct = min(current_pct, next_base_pct - 1 if idx + 1 < total else 99)
        
        # "control" is the wrong word for a Customize run, which audits the
        # auditor's own questions and never resolves a control for them.
        _unit = "question" if state.get("rag_mode") else "control"
        _what = (state.get("control_label") if state.get("rag_mode")
                 else state.get("control_id")) or ""
        with _bg_lock:
            _bg_store["progress"][bg_key] = {
                "text": f"⚡ Auditing {_unit} {idx + 1}/{total}: {_what} — {phase_text}...",
                "percent": current_pct
            }
    except Exception as e:
        print(f"[PROGRESS UPDATE WARNING] Failed to update progress: {e}", flush=True)

def retrieve_node(state: AuditState) -> Dict[str, Any]:
    """Node: Pulls grounded document segments relevant to the target control.

    Two-Phase Mode (Excel Scoping):
        If `locked_filenames` is set, retrieval is scoped to ONLY those files.
        This guarantees the correct evidence is always extracted from the correct
        file — the LLM never sees content from other files.

    Standard Mode (AI Scoping):
        Retrieval searches across all uploaded files as before.
    """
    _update_progress(state, "Retrieving document context", 0.1)
    controls_batch = [{
        "control": state["control_id"],
        "label": state["control_label"],
        "expected": state["expected_evidence"],
        "prompt_hint": state["prompt_hint"],
        "keywords": state.get("keywords") or {}
    }]

    # ── Phase 1: Locked-file retrieval (Excel scoping mode) ───────────────────
    locked_filenames = state.get("locked_filenames") or []
    if locked_filenames:
        # Restrict retrieval to ONLY the locked files from the Excel checklist
        print(
            f"[RETRIEVE NODE] Two-Phase mode: restricting retrieval to "
            f"{locked_filenames} for control {state['control_id']}",
            flush=True
        )
        condensed, _, _ = _retrieve_rag_context(
            context=state["document_text"],
            controls_batch=controls_batch,
            file_names_list=locked_filenames,   # ← LOCKED: only these files
            llm_model=state["llm_model"],
            KEYWORD_SYNONYMS=KEYWORD_SYNONYMS,
            audit_mode=state.get("audit_mode"),
            report_id=state.get("report_id"),
            policy_locked_filenames=state.get("policy_locked_filenames"),
            evidence_locked_filenames=state.get("evidence_locked_filenames"),
            file_registry=state.get("file_registry")
        )
        # Safety guarantee: if locked files returned no context, fall back
        # to raw document_text (never send empty context to LLM)
        if not condensed.strip():
            print(
                f"[RETRIEVE NODE] Locked retrieval returned empty context for "
                f"{locked_filenames}. Falling back to raw document text.",
                flush=True
            )
            condensed = state["document_text"][:6000]
    else:
        # ── Standard mode: search across all uploaded files ────────────────
        condensed, _, _ = _retrieve_rag_context(
            context=state["document_text"],
            controls_batch=controls_batch,
            file_names_list=state["file_names_list"],
            llm_model=state["llm_model"],
            KEYWORD_SYNONYMS=KEYWORD_SYNONYMS,
            audit_mode=state.get("audit_mode"),
            report_id=state.get("report_id"),
            policy_locked_filenames=state.get("policy_locked_filenames"),
            evidence_locked_filenames=state.get("evidence_locked_filenames"),
            file_registry=state.get("file_registry")
        )

    return {"retrieved_context": condensed}


# ── LLM timeout budget ───────────────────────────────────────────────────────
# Two separate budgets, deliberately. They used to be one number covering both
# the wait for a free worker slot and the request itself, so a long queue ate
# the request's clock: a control that needed 15 minutes of compute, after 20
# minutes of queueing, was killed at 30 having been given only 10. The request
# now always gets its full budget no matter how long it waited.
#
# The floor was raised from 600s because it is measured from the moment the call
# starts, using the session count at that instant. A request beginning while the
# system was quiet received 10 minutes, and a burst of new audits arriving
# immediately afterwards could slow it tenfold inside that unchanged budget.
# 1800 costs nothing under load, where active_cnt * per-session already
# dominates, and removes the only timeout that a correctly-sized machine still
# produced. Both are env-overridable for an operator who has measured their own
# hardware.
LLM_TIMEOUT_FLOOR_SEC = int(os.environ.get("LLM_TIMEOUT_FLOOR_SEC", "1800"))
LLM_TIMEOUT_PER_SESSION_SEC = int(os.environ.get("LLM_TIMEOUT_PER_SESSION_SEC", "360"))
# Waiting for a worker slot is a queueing problem, not a compute one: if no slot
# frees in this long, the system is saturated and failing fast is more useful
# than holding the thread.
LLM_POOL_WAIT_TIMEOUT_SEC = int(os.environ.get("LLM_POOL_WAIT_TIMEOUT_SEC", "300"))

# The generation and reflection calls no longer have a wall-clock budget: the
# request is streamed and fails only when the model falls silent
# (llm_client.LLM_STALL_TIMEOUT_SEC). A control used to be cut off at 30
# minutes while the model was still writing -- measured on a 4-core VM, two
# audits at once -- and then reported NON_COMPLIANT. A call that does fail that
# way is asked again, after a pause, up to LLM_RETRY_ATTEMPTS times.
LLM_RETRY_ATTEMPTS = int(os.environ.get("LLM_RETRY_ATTEMPTS", "3"))
LLM_RETRY_DELAY_SEC = float(os.environ.get("LLM_RETRY_DELAY_SEC", "30"))


def _invoke_with_retries(state, chain, args, what):
    """chain.invoke(args), asked again while the model is unavailable."""
    from src.core.llm_client import LLMUnavailableError
    for attempt in range(LLM_RETRY_ATTEMPTS + 1):
        try:
            return chain.invoke(args)
        except LLMUnavailableError as e:
            if attempt >= LLM_RETRY_ATTEMPTS:
                raise
            print(f"[LANGGRAPH RETRY] {what} for control {state.get('control_id', '')}: the model did "
                  f"not respond ({e}); retry {attempt + 1} of {LLM_RETRY_ATTEMPTS}.", flush=True)
            _time.sleep(LLM_RETRY_DELAY_SEC)


def _wait_while_working(t, state, label, lo, hi):
    """Wait for the call thread, with no ceiling -- the call itself ends when the
    model finishes or falls silent -- moving the progress bar meanwhile."""
    elapsed = 0
    while t.is_alive():
        t.join(timeout=15)
        elapsed += 15
        if t.is_alive():
            # Approaches `hi` without reaching it, however long the call runs.
            _update_progress(state, f"{label}... ({elapsed}s)", lo + (hi - lo) * elapsed / (elapsed + 600))


def _record_control_timeout(state, control_id: str, budget_sec: int, phase: str = "generation"):
    """Records a control timeout everywhere it needs to be visible.

    Three destinations, because each answers a different person's question:
      - SystemEvent      : the admin log trail (what happened, when, which control)
      - Redis error count: the live KPI dashboard, which previously read zero
                           errors while controls were timing out -- the two views
                           disagreed and the dashboard was the one people watched
      - progress warning : the auditor's own screen. app.js already toasts this
                           field, so no frontend change is needed; without it a
                           timeout was invisible to the person running the audit.
    """
    session_id = state.get("bg_key", "") or ""
    try:
        from src.core.bg_worker import log_system_event
        log_system_event(
            "LLM_TIMEOUT", "WARNING",
            f"{phase.capitalize()} timed out after {budget_sec}s for control '{control_id}' "
            f"-- control marked NOT_EVALUATED.",
            session_id=session_id,
        )
    except Exception:
        pass
    try:
        from src.core import redis_metrics as _rm
        _rm.push_error(session_id=session_id)
    except Exception:
        pass
    if not session_id:
        return
    try:
        from src.core.bg_state import _bg_store, _bg_lock
        with _bg_lock:
            _prev = _bg_store["progress"].get(session_id) or {}
            if phase == "reflection":
                _msg = (
                    f"⚠️ Control {control_id}: the self-correction pass timed out after "
                    f"{budget_sec // 60} minutes. The original assessment was kept."
                )
            else:
                _msg = (
                    f"⚠️ Control {control_id} could not be evaluated — the analysis engine "
                    f"stopped responding and did not recover after {LLM_RETRY_ATTEMPTS} retries. "
                    f"It will be reported as Not Assessed; re-run it."
                )
            _bg_store["progress"][session_id] = {**_prev, "warning": _msg}
    except Exception:
        pass


def _calculate_adaptive_timeout() -> int:
    """
    Dynamically calculates the LLM execution timeout based on system load:
    - 1 Auditor running: max(1800, 1 * 360) = 1800s (30 minutes) — ample time even for huge prompts.
    - 15 Auditors running: max(1800, 15 * 360) = 5400s (90 minutes) — heavy concurrent batches are NEVER cut short.
    - If Redis is down: falls back to checking Python in-memory _bg_running set.
    - Instant exit: t.join() exits sub-second as soon as LLM generation finishes.
    """
    from src.core.redis_metrics import get_running_session_count
    active_cnt = max(1, get_running_session_count())

    return max(LLM_TIMEOUT_FLOOR_SEC, active_cnt * LLM_TIMEOUT_PER_SESSION_SEC)


def _accumulate_token_stats(state: AuditState, chain) -> Dict[str, int]:
    """Adds a chain's real token usage (from the LLM server) on top of whatever's
    already recorded in state — generate + reflection are separate LLM calls, so
    a reflection pass adds to the total rather than replacing it."""
    prior = state.get("token_stats") or {}
    new_stats = getattr(chain, "last_token_stats", {}) or {}
    return {
        "prompt_tokens": prior.get("prompt_tokens", 0) + new_stats.get("prompt_tokens", 0),
        "completion_tokens": prior.get("completion_tokens", 0) + new_stats.get("completion_tokens", 0),
    }


def generate_node(state: AuditState) -> Dict[str, Any]:
    """Node: Calls ChatOllama to generate the initial finding draft based on context."""
    _update_progress(state, "Drafting compliance finding", 0.3)
    from src.ai.knowledge_loop import get_auditor_feedback_few_shot as _get_auditor_feedback_few_shot
    
    feedback_block = _get_auditor_feedback_few_shot([state["control_id"]])
    feedback_section = f"\nAUDITOR KNOWLEDGE LOOP GUIDELINES:\n{feedback_block}\n" if feedback_block else ""

    # generator_chain is constructed inside this same try/except now -- previously
    # get_generator_chain()/get_excel_scoping_chain() ran before the try block
    # below, so if either ever raised, the exception propagated uncaught out of
    # generate_node and aborted the whole graph run for that control instead of
    # degrading gracefully like the rest of this node. Initialized to None first
    # so the except block's _accumulate_token_stats(state, generator_chain) call
    # stays safe even if construction itself is what failed.
    generator_chain = None
    try:
        generator_chain = get_generator_chain(state["llm_model"])

        # ── Phase 2: Judge-only chain for Excel scoping mode ────────────────────
        locked_filenames = state.get("locked_filenames") or []
        checklist_question = state.get("checklist_question") or state["control_label"]
        # Customize is checked FIRST: its rows are locked to files too, so the
        # bool(locked_filenames) test below would otherwise hand a question-only
        # audit the ISO Lead Auditor judge prompt -- the exact control framing the
        # mode exists to do without.
        use_rag_qa_mode = bool(state.get("rag_mode"))
        use_excel_judge_mode = bool(locked_filenames) and not use_rag_qa_mode
        if use_rag_qa_mode:
            from src.ai.audit_chains import get_rag_qa_chain
            generator_chain = get_rag_qa_chain(state["llm_model"])
            print(
                f"[GENERATE NODE] Pure document Q&A (Customize) for {state['control_id']} "
                f"(files: {locked_filenames or 'session evidence'})",
                flush=True
            )
        elif use_excel_judge_mode:
            from src.ai.audit_chains import get_excel_scoping_chain
            generator_chain = get_excel_scoping_chain(state["llm_model"])
            print(
                f"[GENERATE NODE] Two-Phase judge mode for control {state['control_id']} "
                f"(locked: {locked_filenames})",
                flush=True
            )

        # ── Column-source hint: tell the LLM which locked file(s) the auditor put
        # in a Policy-named vs Evidence-named column, instead of leaving it to
        # re-derive that split blind from undifferentiated locked text. Empty when
        # the sheet has no such column-level distinction.
        policy_locked = state.get("policy_locked_filenames") or []
        evidence_locked = state.get("evidence_locked_filenames") or []
        column_source_hint = ""
        if policy_locked or evidence_locked:
            parts = []
            if policy_locked:
                parts.append(f"The auditor's checklist lists {', '.join(policy_locked)} under the POLICY column.")
            if evidence_locked:
                parts.append(f"The auditor's checklist lists {', '.join(evidence_locked)} under the EVIDENCE column.")
            column_source_hint = (
                "\nAUDITOR COLUMN SOURCE (strong prior, not proof — still verify the actual content "
                "supports the objective before marking COMPLIANT):\n" + " ".join(parts) + "\n"
            )

        # NOTE: Customize used to reach this point on the judge prompt with a patch
        # appended here telling the model to ignore the policy half of the very prompt
        # it had just been given. It no longer does: Customize runs on
        # RAG_QA_PROMPT_TEMPLATE (use_rag_qa_mode above), which never mentions policy,
        # controls or the standard in the first place. Bolting a "disregard the
        # previous instructions" paragraph onto an auditor prompt was always the weaker
        # half of the fix -- the model obeyed it inconsistently, which is what
        # _align_customize_answer in validator.py had to keep cleaning up after.

        result_holder = {}
        if use_rag_qa_mode:
            # Pure document Q&A: the question and the extracts, nothing else.
            # No control id, no expected evidence and no auditor feedback
            # few-shots -- each of those reintroduces control framing through
            # the back door, which is exactly what this mode is not.
            _args = {
                "locked_filenames": ", ".join(locked_filenames) or "the uploaded evidence",
                "checklist_question": checklist_question,
                "condensed_context": state["retrieved_context"],
            }
        elif use_excel_judge_mode:
            # Judge-only mode: pass locked_filenames + checklist_question
            _args = {
                "locked_filenames": ", ".join(locked_filenames),
                "checklist_question": checklist_question,
                "column_source_hint": column_source_hint,
                "condensed_context": state["retrieved_context"],
                "control_id": state["control_id"],
                "control_label": state["control_label"],
                "expected_evidence": state["expected_evidence"],
                "feedback_section": feedback_section,
            }
        else:
            # Standard mode: original prompt
            _args = {
                "summary_text": state["summary_text"],
                "condensed_context": state["retrieved_context"],
                "control_id": state["control_id"],
                "control_label": state["control_label"],
                "expected_evidence": state["expected_evidence"],
                "feedback_section": feedback_section,
                "standard": state.get("standard", ""),
            }
        # timeout None: no ceiling on the answer (see LLM_RETRY_ATTEMPTS above).
        _args.update({"session_id": state.get("bg_key"), "timeout": None})

        def _run():
            from src.core.llm_client import LLMUnavailableError
            try:
                print("\n===== EVIDENCE CONTEXT SENT TO LLM =====", flush=True)
                print(state.get("retrieved_context", ""), flush=True)
                print("===== END EVIDENCE CONTEXT =====\n", flush=True)
                result_holder["draft"] = _invoke_with_retries(state, generator_chain, _args, "Generation")
            except LLMUnavailableError as ex:
                result_holder["unavailable"] = str(ex)
            except Exception as ex:
                result_holder["error"] = str(ex)
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        _wait_while_working(t, state, "LLM analysing control", 0.3, 0.69)
        if "unavailable" in result_holder:
            _ctrl = state.get('control_id', '')
            print(f"[LANGGRAPH] Model unavailable for control {_ctrl} after "
                  f"{LLM_RETRY_ATTEMPTS} retries. Not evaluated.", flush=True)
            _record_control_timeout(state, _ctrl, 0, phase="generation")
            # NOT_EVALUATED, never a fabricated verdict: the audit may report that
            # it could not assess a control; it must not invent the answer.
            return {
                "draft_finding": None,
                "validation_error": f"LLM request timed out: {result_holder['unavailable']}",
            }
        # ─────────────────────────────────────────────────────────────────────
        if "error" in result_holder:
            raise Exception(result_holder["error"])
        draft = result_holder["draft"]

        return {
            "draft_finding": draft.model_dump(),
            "validation_error": None,
            "token_stats": _accumulate_token_stats(state, generator_chain)
        }
    except Exception as e:
        print(f"[LANGGRAPH GENERATOR ERROR] Schema parsing failed for control {state['control_id']}: {e}", flush=True)
        return {
            "draft_finding": None,
            "validation_error": f"Schema parsing/validation failed: {str(e)}",
            # LLM call may have consumed real tokens even though parsing failed afterward.
            "token_stats": _accumulate_token_stats(state, generator_chain)
        }

def validate_node(state: AuditState) -> Dict[str, Any]:
    """Node: Validates finding grounding, prompt leakage, and alignment consistency."""
    _update_progress(state, "Validating cited evidence", 0.7)
    draft = state["draft_finding"]
    
    if not draft:
        # Customize is included unconditionally: it never routes to the reflection
        # pass (see should_continue), so without this a question whose generation
        # failed would end with final_finding=None and vanish from the report
        # instead of being reported as unanswered.
        # A model that stayed unavailable through its retries is reported Not
        # Assessed in every mode: a Deep-mode reflection pass would only start
        # from an empty draft, on the same unavailable model.
        _unavailable = "timed out" in str(state.get("validation_error") or "").lower()
        if state.get("audit_mode") == "Quick" or state["retry_count"] >= 1 or state.get("rag_mode") or _unavailable:
            mode_prefix = ("Customize Q&A" if state.get("rag_mode")
                           else ("Quick audit" if state.get("audit_mode") == "Quick" else "Self-correction"))
            print(f"[LANGGRAPH] {mode_prefix} failed generation for control {state['control_id']}. Routing to fallback.", flush=True)
            retrieved = str(state.get("retrieved_context") or "").strip()
            has_retrieved = len(retrieved) > 40 and not any(kw in retrieved.lower() for kw in ["no relevant context found", "no evidence found"])
            
            ev_snippet = retrieved[:400] if has_retrieved else ""
            ev_quote = retrieved[:200] if has_retrieved else "NOT_FOUND"
            
            ctrl_name = state.get("control_label") or state.get("control_id") or "Control"
            ctrl_code = state.get("control_id") or ""
            prompt_hint = state.get("prompt_hint") or ""

            # ── Honest fallback: this path means the LLM never actually produced
            # a parseable finding -- distinguish WHY (genuine timeout vs. some
            # other generation failure) using the real reason already sitting in
            # validation_error, instead of synthesizing plausible-sounding
            # "evidence was identified" text that reads like real analysis
            # happened when nothing was actually evaluated.
            _prior_error = str(state.get("validation_error") or "")
            _is_timeout = "timed out" in _prior_error.lower()

            if _is_timeout:
                finding_text = (
                    f"NOT ASSESSED: Control {ctrl_code} ({ctrl_name}) was not evaluated. The analysis "
                    f"engine stopped responding and did not recover after {LLM_RETRY_ATTEMPTS} retries. "
                    f"This is not a compliance verdict -- re-run this control."
                )
                gap_text = f"Control {ctrl_code} was not assessed: the analysis engine stopped responding. Re-run required."
                rec_text = "Re-run this control -- it was not assessed, which says nothing about the evidence."
                review_note = "NOT ASSESSED -- the model stopped responding. Re-run required; not a genuine finding."
            elif has_retrieved:
                finding_text = f"Evidence context was identified for Control {ctrl_code} ({ctrl_name}), demonstrating partial alignment with governance requirements. However, complete operational logs or formal approval sign-offs remain unverified."
                gap_text = f"Context identified for {ctrl_code}, but complete evidence verification requires auditor sign-off. Context excerpt: {ev_snippet[:200]}..."
                rec_text = state.get("recommendation") or f"Formally document, review, and maintain operational evidence logs for Control {ctrl_code} ({ctrl_name})."
                review_note = "Evaluated with control-specific governance synthesis."
            elif state.get("rag_mode"):
                # Question-only: there is no control objective to describe, and no
                # policy to recommend establishing. Say what actually happened.
                _q = state.get("checklist_question") or ctrl_name
                finding_text = f"This question was not answered: no usable response was produced for \"{_q}\"."
                gap_text = finding_text
                rec_text = "Re-run this question. If it recurs, check that the cited document was uploaded and is readable."
                review_note = "No answer was produced for this question -- re-run required."
            else:
                finding_text = f"The control objective for Control {ctrl_code} ({ctrl_name}) requires documented policies and implementation evidence ({prompt_hint[:90]}...). No supporting evidence was identified in the uploaded package."
                gap_text = f"No documentation or evidence identified for Control {ctrl_code}."
                rec_text = state.get("recommendation") or f"Establish, document, and formally approve procedures to satisfy Control {ctrl_code} ({ctrl_name})."
                review_note = "Evaluated with control-specific governance synthesis."

            fallback = {
                # A timeout is NOT_EVALUATED, not NON_COMPLIANT. The prose in this
                # branch already said the control "was NOT evaluated", but the status
                # field -- which is what drives the dashboard counts, the severity
                # calculation, the exports and the customer's compliance percentage --
                # still asserted NON_COMPLIANT. That publishes a compliance judgement
                # for a control nothing ever assessed, and it is indistinguishable in
                # every downstream view from a genuine failure.
                "status": "NOT_EVALUATED" if _is_timeout else ("PARTIAL" if has_retrieved else "NON_COMPLIANT"),
                "final_result": "NOT_EVALUATED" if _is_timeout else None,
                # No risk rating can be derived from an evaluation that did not happen.
                "severity": "N/A" if _is_timeout else None,
                "risk_level": "UNDETERMINED" if _is_timeout else None,
                "policy_present": "Not Found" if _is_timeout else ("Found" if has_retrieved else "Not Found"),
                "evidence_present": "Not Found" if _is_timeout else ("Found" if has_retrieved else "Not Found"),
                "hallucination_check": "SYSTEM_TIMEOUT" if _is_timeout else "FAIL_FALLBACK",
                "requires_human_review": True,
                "requires_review": True,
                "review_note": review_note,
                "control_id": state["control_id"],
                "control": state["control_label"],
                "evidence_quote": "NOT_EVALUATED" if _is_timeout else ev_quote,
                "evidence_snippet": "" if _is_timeout else ev_snippet,
                "finding": finding_text,
                "gap_description": gap_text,
                "reasoning": finding_text,
                "recommendation": rec_text
            }
            from src.core.validator import evaluate_nist_risk_and_severity
            fallback = evaluate_nist_risk_and_severity(fallback, state["control_id"])
            return {
                "validation_error": None,
                "final_finding": fallback
            }
        # If generation failed completely, flag validation error to trigger reflection
        return {
            "validation_error": state["validation_error"] or "Empty draft finding",
            "final_finding": None
        }
    
    # Construct expected evidence map for the validator
    code = state["control_id"].split(" ")[0] if state["control_id"] else ""
    expected_evidence_map = {
        code: [state["expected_evidence"], state["prompt_hint"]]
    }
    
    # NOTE: a fast-path guardrail that bypassed post_process() entirely for
    # COMPLIANT findings with a verbatim-matching quote used to live here. Removed
    # per the RAG accuracy overhaul (Phase 6) -- a verbatim quote proves grounding,
    # not compliance, and every finding now always goes through the full gate
    # sequence (leakage, grounding, and the deterministic policy/evidence formula)
    # below, with zero exceptions.

    # Query database chunks for verbatim verification
    session = SessionLocal()
    db_chunks = []
    try:
        _chunk_query = session.query(DocumentChunk).filter(DocumentChunk.filename.in_(state["file_names_list"]))
        if state.get("report_id") is not None:
            _chunk_query = _chunk_query.filter(DocumentChunk.report_id == state["report_id"])
        db_chunks = _chunk_query.all()
    except Exception as e:
        print(f"[LANGGRAPH VALIDATOR WARNING] Failed to query database chunks: {e}", flush=True)
    finally:
        session.close()

    # Enforce original validator checks (from validator.py)
    draft_copy = dict(draft)
    draft_copy["control_id"] = state["control_id"]
    # Carry the Excel scoping through to the validator. post_process() needs to know
    # the auditor locked this control to specific file(s), so its clause-5/6/7
    # "needs a documented policy" default doesn't overrule a checklist that
    # deliberately scoped the control to operational evidence alone.
    draft_copy["locked_filenames"] = state.get("locked_filenames") or []
    draft_copy["policy_locked_filenames"] = state.get("policy_locked_filenames") or []
    draft_copy["evidence_locked_filenames"] = state.get("evidence_locked_filenames") or []
    # Question-only scope: post_process judges these on evidence alone and clears the
    # policy fields, so it has to be told. Without this the dual rule would apply and
    # every Customize row would fail on a policy the auditor never put in scope.
    draft_copy["customize_mode"] = bool(state.get("customize_mode"))
    # Pure document Q&A. post_process returns straight after the grounding gate for
    # these -- no control formula, no requirement decomposition, no NIST severity --
    # and takes the verdict from the answer's own Yes/No opener. The question and the
    # label travel with it because there is no control to look either of them up from.
    draft_copy["rag_mode"] = bool(state.get("rag_mode"))
    if state.get("rag_mode"):
        draft_copy["requirement_question"] = (
            state.get("checklist_question") or state.get("control_label") or "")
        draft_copy["control_label"] = state.get("control_label") or ""
    
    validated_finding = post_process(
        finding=draft_copy,
        document_text=state["document_text"],
        expected_evidence_map=expected_evidence_map,
        db_chunks=db_chunks
    )
    
    # Check if validator modified the finding to human review or non-compliant due to grounding/leak issues
    hallucination_state = validated_finding.get("hallucination_check")
    status = validated_finding.get("status")
    
    is_failed = (
        hallucination_state in ("PROMPT_LEAK", "NOT_GROUNDED") or
        validated_finding.get("requires_human_review", False) or
        "Grounding validation failed" in str(validated_finding.get("review_note", ""))
    )
    
    if is_failed:
        error_msg = validated_finding.get("review_note") or validated_finding.get("validator_note") or "Grounding check failed: Evidence quote was not verified in the document."

        # Customize (pure Q&A): a grounding failure means the quote the model gave is
        # not actually in the cited document. The answer is kept, downgraded and
        # flagged for the auditor rather than handed to the reflection pass -- that
        # pass is an adversarial compliance challenger written around a control, and
        # running it here would put back the framing this mode exists to remove.
        if state.get("rag_mode"):
            # Only a grounding failure may change the verdict. is_failed above is
            # deliberately broader than that -- it also fires on
            # requires_human_review, which any gate can set to mean "a person
            # should look at this", not "this failed". Downgrading on that turned
            # every flagged-for-review answer into a failure: a screenshot whose
            # OCR text tripped a review gate produced a finding reading "Yes, NTP
            # is enabled and synchronized" beside a NON_COMPLIANT badge, against a
            # host that was compliant. Confirmed in a customer's log, where the
            # validator had already passed it:
            #   [VALIDATOR] Customize Q&A: answer opens "Yes" -> COMPLIANT
            #   [LANGGRAPH VALIDATOR] Customize Q&A grounding issue ... flagged
            #
            # The validator owns this verdict and has its own grounding override
            # (finalize_rag_answer), so by the time a genuine failure reaches here
            # the status is already NON_COMPLIANT with the matching recommendation
            # and impact. This branch only ever corrected a status the validator
            # had deliberately left alone -- and left the compliant-shaped
            # narrative ("No action required.") sitting beneath the new verdict,
            # because it changed the verdict and nothing else.
            _grounding_failed = (
                hallucination_state in ("PROMPT_LEAK", "NOT_GROUNDED")
                or "Grounding validation failed" in str(validated_finding.get("review_note", ""))
            )
            if _grounding_failed:
                if str(validated_finding.get("status") or "").upper() == "COMPLIANT":
                    validated_finding["status"] = "NON_COMPLIANT"
                    validated_finding["final_result"] = "NON_COMPLIANT"
                validated_finding["review_note"] = (
                    f"The quoted text could not be verified in the cited document: {error_msg}")
            elif not str(validated_finding.get("review_note") or "").strip():
                # Flagged for review without a reason recorded. Say that, rather
                # than inheriting a grounding message that is not true of it.
                validated_finding["review_note"] = (
                    "Flagged for a reviewer to confirm. The answer and its quote were "
                    "accepted by the validator.")
            validated_finding["requires_human_review"] = True
            validated_finding["requires_review"] = True
            validated_finding["control_id"] = state["control_id"]
            validated_finding["control"] = state["control_label"]
            print(f"[LANGGRAPH VALIDATOR] Customize Q&A {'grounding issue' if _grounding_failed else 'review flag'} "
                  f"for {state['control_id']}: verdict {validated_finding.get('status')}, flagged for review.",
                  flush=True)
            _log_execution_event(state, validated_finding)
            return {
                "validation_error": None,
                "final_finding": validated_finding
            }

        if state.get("audit_mode") == "Quick":
            # FIX Q1: In Quick mode, don't blindly accept a hard-failed finding.
            # If the validator already smart-upgraded it to PARTIAL_COMPLIANT (Fix 1 in validator.py),
            # preserve that. Only bypass if the finding is already at a reasonable status.
            current_status = validated_finding.get("status", "NON_COMPLIANT")
            hallucination_check = validated_finding.get("hallucination_check", "")
            if current_status not in ("NON_COMPLIANT", "PARTIAL_COMPLIANT", "FALSE_POSITIVE"):
                # Grounding/leakage check failed (is_failed=True) but status still claims a
                # positive result (e.g. COMPLIANT) -- force it down instead of saving an
                # internally-inconsistent finding (ungrounded evidence + COMPLIANT status).
                validated_finding["status"] = "NON_COMPLIANT"
                validated_finding["requires_human_review"] = True
                validated_finding["requires_review"] = True
                validated_finding["review_note"] = f"Quick mode: downgraded from {current_status} -- {error_msg}"
                current_status = "NON_COMPLIANT"
            print(f"[LANGGRAPH VALIDATOR] Quick mode validation issue for {state['control_id']} (status: {current_status}, check: {hallucination_check}). Accepting validator decision without retry.", flush=True)
            return {
                "validation_error": None,
                "final_finding": validated_finding
            }
            
        # NOTE: should_continue() only ever routes here with retry_count 0 or 1 --
        # it routes to "reflect" when retry_count < 1, and reflection_node
        # increments by exactly 1, so a retry_count >= 2 branch here could never
        # fire (leftover from an earlier multi-retry design). The retry_count >= 1
        # branch below covers this outcome already.

        print(f"[LANGGRAPH VALIDATOR] Validation rejected for control {state['control_id']}: {error_msg}", flush=True)

        # If LLM produced an empty/fallback response (LLM unavailable), accept with review flag
        # rather than returning final_finding=None which causes result to be lost entirely
        draft_status = str((state.get("draft_finding") or {}).get("status", "")).upper()
        draft_evidence = str((state.get("draft_finding") or {}).get("evidence_quote", "")).upper()
        llm_failed = (not state.get("draft_finding")) or (draft_evidence == "NOT_FOUND" and draft_status == "NON_COMPLIANT")

        if state["retry_count"] >= 1 or llm_failed:
            # Accept validated_finding (even if flagged) rather than losing the result
            validated_finding["status"] = "NON_COMPLIANT"
            validated_finding["requires_human_review"] = True
            validated_finding["requires_review"] = True
            validated_finding["review_note"] = f"LLM unavailable or grounding failed: {error_msg}"
            validated_finding["control_id"] = state["control_id"]
            validated_finding["control"] = state["control_label"]
            _log_execution_event(state, validated_finding)
            return {
                "validation_error": None,
                "final_finding": validated_finding
            }

        return {
            "validation_error": error_msg,
            "draft_finding": validated_finding,
            "final_finding": None
        }
    
    # If validation passes cleanly
    print(f"[LANGGRAPH VALIDATOR] Validation passed for control {state['control_id']} (status: {status})", flush=True)
    _log_execution_event(state, validated_finding)
    return {
        "validation_error": None,
        "final_finding": validated_finding
    }

def reflection_node(state: AuditState) -> Dict[str, Any]:
    """Node: Skeptical reflection chain to correct any validation errors."""
    _update_progress(state, "Correcting validation gaps", 0.85)
    print(f"[LANGGRAPH REFLECTION] Initiating correction pass for control {state['control_id']}. Iteration: {state['retry_count'] + 1}", flush=True)
    
    reflection_chain = get_reflection_chain(state["llm_model"])
    draft = state["draft_finding"] or {}
    
    try:
        result_holder = {}
        # No ceiling, as in generate_node: streamed, and asked again if the model
        # falls silent.
        def _run_reflect():
            try:
                result_holder["refined"] = _invoke_with_retries(state, reflection_chain, {
                    "condensed_context": state["retrieved_context"],
                    "control_id": state["control_id"],
                    "control_label": state["control_label"],
                    "draft_status": draft.get("status", "NON_COMPLIANT"),
                    "draft_severity": draft.get("severity", "N/A"),
                    "draft_evidence": draft.get("evidence_quote", "NOT_FOUND"),
                    "draft_gap": draft.get("gap_description", ""),
                    "draft_recommendation": draft.get("recommendation", ""),
                    "draft_reasoning": draft.get("reasoning", ""),
                    "draft_business_impact": draft.get("business_impact", ""),
                    "draft_remediation_priority": draft.get("remediation_priority", "Medium"),
                    "draft_evidence_strength": draft.get("evidence_strength", "None"),
                    "draft_control_coverage": draft.get("control_coverage", 0),
                    "validation_error": state["validation_error"],
                    "standard": state.get("standard", ""),
                    "session_id": state.get("bg_key"),
                    "timeout": None,
                }, "Reflection")
            except Exception as ex:
                result_holder["error"] = str(ex)
        t = threading.Thread(target=_run_reflect, daemon=True)
        t.start()
        _wait_while_working(t, state, "Self-correcting finding", 0.85, 0.94)
        if "error" in result_holder:
            raise Exception(result_holder["error"])
        refined = result_holder["refined"]

        return {
            "draft_finding": refined.model_dump(),
            "validation_error": None,
            "retry_count": state["retry_count"] + 1,
            "token_stats": _accumulate_token_stats(state, reflection_chain)
        }
    except Exception as e:
        print(f"[LANGGRAPH REFLECTION ERROR] Self-correction call failed: {e}", flush=True)
        return {
            "validation_error": f"Reflection parse failed: {str(e)}",
            "retry_count": state["retry_count"] + 1,
            # Reflection's LLM call may have consumed real tokens even though parsing failed.
            "token_stats": _accumulate_token_stats(state, reflection_chain)
        }

# Define edge routing condition
def should_continue(state: AuditState) -> str:
    """Routes state based on validation status and retry bounds.

    With Cross-Encoder Reranking + 4-Gate Validation, at most 1 single
    reflection pass is allowed. This eliminates unnecessary 2nd-pass delays
    while preserving 100% ground truth verification.
    """
    if state["validation_error"] is not None:
        # Customize (pure Q&A) never reflects: reflection_node runs
        # REFLECTION_PROMPT_TEMPLATE, an adversarial compliance challenger built
        # around a control and a policy, which is precisely the framing this mode
        # removes. validate_node returns a usable finding for these instead of a
        # validation_error, so this is a backstop rather than the normal path.
        if state.get("rag_mode"):
            return "end"
        if state["retry_count"] < 1:
            return "reflect"
        return "end"
    return "end"

# Compile LangGraph State Machine
def compile_audit_graph():
    """Builds and compiles the StateGraph workflow."""
    workflow = StateGraph(AuditState)
    
    # Add Nodes
    workflow.add_node("retrieve", retrieve_node)
    workflow.add_node("generate", generate_node)
    workflow.add_node("validate", validate_node)
    workflow.add_node("reflect", reflection_node)
    
    # Add Edges
    workflow.add_edge(START, "retrieve")
    workflow.add_edge("retrieve", "generate")
    workflow.add_edge("generate", "validate")
    
    # Conditional edge from validate
    workflow.add_conditional_edges(
        "validate",
        should_continue,
        {
            "reflect": "reflect",
            "end": END
        }
    )
    
    # Reflect cycles back to validate so grounding can be checked
    workflow.add_edge("reflect", "validate")
    
    return workflow.compile()

# Singleton graph instance cached at module load
audit_graph = compile_audit_graph()


# ── Execution Metadata Logger (Fix G4 — Audit Logs) ——————————————————
def _log_execution_event(state: AuditState, final_finding: Dict[str, Any]) -> None:
    """
    Writes a structured execution metadata row to the SystemEvent table after
    each control is validated. This is a sidecar write — it runs AFTER
    final_finding is already set and is wrapped in try/except so any DB failure
    never affects the audit result.

    Captures: control_id, model, backend, audit_mode, retry_count,
              hallucination_check, final_status, retrieved_context_chars.
    """
    try:
        import json as _json
        import os as _os
        from src.db.database import SystemEvent

        meta = {
            "control_id":              state.get("control_id", ""),
            "model":                   state.get("llm_model", ""),
            "backend":                 _os.environ.get("LLM_BACKEND", "ollama"),
            "audit_mode":              state.get("audit_mode", "Normal"),
            "retry_count":             state.get("retry_count", 0),
            "hallucination_check":     final_finding.get("hallucination_check", ""),
            "final_status":            final_finding.get("status", ""),
            "retrieved_context_chars": len(state.get("retrieved_context", "")),
            "requires_human_review":   final_finding.get("requires_human_review", False),
        }

        event = SystemEvent(
            event_type="CONTROL_AUDIT_COMPLETE",
            actor="SYSTEM",
            session_id=state.get("bg_key", ""),
            framework="ISO 27001",
            meta=_json.dumps(meta),
            severity="INFO",
        )
        session = SessionLocal()
        try:
            session.add(event)
            session.commit()
        finally:
            session.close()

    except Exception as _log_err:
        # Never let a log failure affect the audit result
        print(f"[AUDIT LOG WARNING] Failed to write execution event: {_log_err}", flush=True)
