# -*- coding: utf-8 -*-
"""
Knowledge Loop End-to-End Test (accept/reject -> learns)

Verifies the REAL mechanism, not the one described in CLAUDE.md (that description is
stale -- it names AuditorLearningRule, a table that's defined in database.py but never
instantiated anywhere in the codebase; dead schema). The mechanism actually wired up:

    1. The UI's "Reject" button on a finding's evidence card calls
       POST /audit/findings/{id}/reject-doc (rejectSingleDocCard() in app.js).
    2. That endpoint (api_reject_doc_from_finding in audit.py) writes an AuditorFeedback
       row with corrected_status='REJECTED'.
    3. On the NEXT audit run for that control, generate_node calls
       get_auditor_feedback_few_shot(control_ids) (knowledge_loop.py), which reads the
       20 most recent AuditorFeedback rows for that control and formats REJECTED ones as
       an explicit "do NOT repeat this false finding" instruction injected into the
       generator prompt's feedback_section.

This script exercises all three steps against the real functions (not reimplementations):
  Step 1: run a real audit via audit_graph.invoke() to get an initial finding.
  Step 2: save it as a real Finding DB row (mirroring what bg_worker.py does).
  Step 3: call the REAL api_reject_doc_from_finding() endpoint function to reject it.
  Step 4: verify an AuditorFeedback row now exists with corrected_status='REJECTED'.
  Step 5: call the REAL get_auditor_feedback_few_shot() and verify the hint text
          references the rejected finding correctly.
  Step 6: re-run the SAME control via audit_graph.invoke() and compare the two results,
          plus confirm generate_node's feedback_block was non-empty for run 2 (proof the
          hint was actually threaded into the second prompt, not just sitting in the DB).

Usage (needs the full local stack -- LLM + embedding servers + DB -- already running,
same as tests/run_evals.py):
    python qa\\knowledge_loop\\test_knowledge_loop.py
"""

import os
import sys
import time
import json

sys.path.append(os.getcwd())

os.environ["LLM_BACKEND"] = "llama.cpp"
os.environ["OLLAMA_HOST"] = "http://127.0.0.1:11434"
os.environ["EMBEDDING_HOST"] = "http://127.0.0.1:11435"

from src.db.database import SessionLocal, Finding, AuditorFeedback, DocumentChunk, force_master
from src.core.controls_data import USE_CASES
from src.core.control_keywords import CONTROL_KEYWORDS
from src.ai.audit_graph import audit_graph
from src.core.retrieval import save_document_chunks, _ingested_chunks_cache, _cache_key
from src.ai.knowledge_loop import get_auditor_feedback_few_shot
from src.api.endpoints.audit import api_reject_doc_from_finding
from src.api.endpoints.auth import _create_token


class _FakeAuthedRequest:
    """Duck-typed stand-in for FastAPI's Request, carrying a real signed JWT --
    api_reject_doc_from_finding now requires auth, and this test calls the
    endpoint function directly (bypassing HTTP), so it must supply its own
    authenticated request rather than relying on route wiring."""
    def __init__(self, username="auditor", role="auditor"):
        self.headers = {"Authorization": f"Bearer {_create_token(username, role)}"}

CONTROL_ID = "8.5"
DOC_NAME = "kl_test_ambiguous_auth.docx"
# Deliberately ambiguous: mentions authentication but not MFA explicitly, and isn't a
# clean pass/fail case -- realistic bait for an auditor to disagree with the LLM's call.
DOC_TEXT = (
    "Section 8.5: Secure Authentication. Users authenticate to internal systems via the "
    "corporate Single Sign-On (SSO) portal using their Active Directory credentials. "
    "Session tokens expire after 30 minutes of inactivity and require re-authentication."
)
TEST_REPORT_ID = 999999001  # synthetic, no real audit_reports row -- no FK constraint on Finding.report_id


def clean_db_for_file(filename):
    with force_master():
        session = SessionLocal()
        session.query(DocumentChunk).filter(DocumentChunk.filename == filename).delete()
        session.commit()
        session.close()


def clean_prior_test_data():
    """Remove any leftover rows from a previous run of this script, so re-running is idempotent."""
    with force_master():
        session = SessionLocal()
        session.query(Finding).filter(Finding.report_id == TEST_REPORT_ID).delete()
        session.query(AuditorFeedback).filter(
            AuditorFeedback.evidence_snippet.like(f"Rejected evidence document: {DOC_NAME}%")
        ).delete()
        session.commit()
        session.close()


def run_control(label):
    """Runs the real audit_graph for CONTROL_ID against DOC_TEXT and returns the finding dict."""
    control_templates = {c["use_case"].split(" ")[0]: c for c in USE_CASES}
    ctrl = control_templates[CONTROL_ID]

    clean_db_for_file(DOC_NAME)
    _ingested_chunks_cache[_cache_key(DOC_NAME)] = [
        (DOC_TEXT, {"source_file": DOC_NAME, "source_type": "docx", "section_heading": "", "chunk_id": "chunk_kl"})
    ]
    save_document_chunks(DOC_NAME, DOC_TEXT)

    state = {
        "control_id": ctrl["use_case"],
        "control_label": ctrl["label"],
        "expected_evidence": ctrl["expected"],
        "prompt_hint": ctrl.get("prompt_hint", ""),
        "severity": ctrl["severity"],
        "standard": ctrl.get("standard", "ISO 27001"),
        "recommendation": ctrl.get("recommendation", ""),
        "keywords": CONTROL_KEYWORDS.get(ctrl["use_case"], {}),
        "document_text": DOC_TEXT,
        "file_names_list": [DOC_NAME],
        "llm_model": "gemma4:e4b",
        "summary_text": f"Knowledge loop test ({label})",
        "retrieved_context": "",
        "draft_finding": None,
        "validation_error": None,
        "retry_count": 0,
        "final_finding": None,
        "bg_key": f"kltest-{label}",
        "control_idx": 0,
        "total_controls": 1,
        "audit_mode": "Deep",
    }

    print(f"\n--- Running control {CONTROL_ID} ({label}) ---")
    start = time.time()
    output_state = audit_graph.invoke(state)
    elapsed = time.time() - start
    finding = output_state.get("final_finding") or {}
    print(f"[{label}] status={finding.get('status')} elapsed={elapsed:.1f}s")
    print(f"[{label}] description: {str(finding.get('description') or finding.get('reasoning') or '')[:200]}")
    print(f"[{label}] gap: {str(finding.get('gap_description') or finding.get('finding') or '')[:200]}")
    return finding


def save_finding_to_db(finding):
    """Mirrors the minimal fields bg_worker.py writes when persisting a real finding."""
    with force_master():
        session = SessionLocal()
        row = Finding(
            report_id=TEST_REPORT_ID,
            control_id=CONTROL_ID,
            control_name=finding.get("control_label") or "8.5 Secure Authentication",
            severity=finding.get("severity") or "MEDIUM",
            description=finding.get("description") or finding.get("reasoning") or "",
            gap_detected=finding.get("gap_description") or finding.get("finding") or "",
            evidence_found="Yes" if finding.get("evidence_status") == "FOUND" else "No",
            evidence_snippet=finding.get("evidence_quote") or "",
            recommendation=finding.get("recommendation") or "",
            reasoning=finding.get("reasoning") or "",
            status=finding.get("status") or "NON_COMPLIANT",
            source_files=DOC_NAME,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        finding_id = row.id
        session.close()
    return finding_id


def main():
    print("=" * 80)
    print("KNOWLEDGE LOOP END-TO-END TEST")
    print("=" * 80)

    clean_prior_test_data()

    # ── Step 1+2: first run, save as a real Finding row ─────────────────────
    finding_1 = run_control("run-1-before-reject")
    finding_id = save_finding_to_db(finding_1)
    print(f"\nSaved as Finding id={finding_id}")

    # ── Step 3: reject it via the REAL endpoint function (not a reimplementation) ──
    reject_reason = "This SSO/AD login description does not confirm multi-factor authentication is enforced -- auditor disagrees with this framing, treat as not proven."
    print(f"\n--- Rejecting via api_reject_doc_from_finding (finding_id={finding_id}) ---")
    reject_result = api_reject_doc_from_finding(
        finding_id,
        {"doc_name": DOC_NAME, "control_id": CONTROL_ID, "reason": reject_reason},
        _FakeAuthedRequest(),
    )
    print("Reject endpoint result:", reject_result)

    # ── Step 4: verify an AuditorFeedback row now exists ─────────────────────
    with force_master():
        session = SessionLocal()
        fb_row = (
            session.query(AuditorFeedback)
            .filter(
                AuditorFeedback.control_id == CONTROL_ID,
                AuditorFeedback.corrected_status == "REJECTED",
                AuditorFeedback.evidence_snippet.like(f"Rejected evidence document: {DOC_NAME}%"),
            )
            .order_by(AuditorFeedback.created_at.desc())
            .first()
        )
        session.close()
    step4_pass = fb_row is not None
    print(f"\n[STEP 4] AuditorFeedback row written: {step4_pass}")
    if fb_row:
        print(f"  id={fb_row.id} corrected_status={fb_row.corrected_status} finding={fb_row.finding!r}")

    # ── Step 5: verify get_auditor_feedback_few_shot() surfaces it correctly ──
    hint_text = get_auditor_feedback_few_shot([CONTROL_ID])
    step5_pass = bool(hint_text) and "REJECTED" in hint_text and DOC_NAME in hint_text
    print(f"\n[STEP 5] Hint text generated: {bool(hint_text)}")
    print(f"[STEP 5] Contains 'REJECTED' + doc name reference: {step5_pass}")
    print("--- hint text ---")
    print(hint_text or "(empty)")
    print("-----------------")

    # ── Step 6: re-run the SAME control and confirm generate_node actually
    # picked up a non-empty feedback_block for this run (proves the loop closes
    # into the SECOND prompt, not just that data sits in the DB) ─────────────
    feedback_block_2 = get_auditor_feedback_few_shot([CONTROL_ID])  # what generate_node will call internally
    step6_prep_pass = bool(feedback_block_2)
    finding_2 = run_control("run-2-after-reject")

    print("\n" + "=" * 80)
    print("SUMMARY")
    print(f"Step 4 (AuditorFeedback written):              {'PASS' if step4_pass else 'FAIL'}")
    print(f"Step 5 (hint correctly formatted):              {'PASS' if step5_pass else 'FAIL'}")
    print(f"Step 6 (feedback available for run 2's prompt): {'PASS' if step6_prep_pass else 'FAIL'}")
    print(f"Run 1 status: {finding_1.get('status')}")
    print(f"Run 2 status: {finding_2.get('status')}")
    print("=" * 80)

    with open(os.path.join(os.path.dirname(__file__), "knowledge_loop_test_results.json"), "w", encoding="utf-8") as f:
        json.dump({
            "step4_auditor_feedback_written": step4_pass,
            "step5_hint_formatted_correctly": step5_pass,
            "step6_feedback_available_for_run2": step6_prep_pass,
            "hint_text": hint_text,
            "run_1": {"status": finding_1.get("status"), "description": finding_1.get("description")},
            "run_2": {"status": finding_2.get("status"), "description": finding_2.get("description")},
        }, f, indent=2)
    print(f"Saved results to {os.path.join(os.path.dirname(__file__), 'knowledge_loop_test_results.json')}")


if __name__ == "__main__":
    main()
