# -*- coding: utf-8 -*-
"""
Hybrid parser+LLM enrichment for VAPT/PQC remediation text.

The deterministic parsers (nmap_parser.py, qualys_parser.py, etc.) are correct
and stay untouched: severity, CVE list, CVSS score, control mapping, title,
evidence -- all of that comes straight from the scanner's own output and this
module never writes to any of it.

Operates on the plain dict shape bg_worker.py already builds (f_dict, i.e. a
Finding run through .to_dict()/asdict()), not on Finding objects directly --
by the point findings are collected into all_findings, they have already been
converted, and re-wrapping them back into Finding just to unwrap again would
be pure overhead with no benefit.

What is fixed here is narrower and more specific: two text fields are the SAME
literal sentence on every finding regardless of what was actually found.
"remediation" is the clear case in nmap_parser.py -- "Investigate service
misconfiguration and apply vendor patches/hardening." is written three times
in that file, verbatim, for every open-port finding it produces, whether the
port is a stale Telnet service or a modern web server with one weak cipher.
"remediation_actionable" has the same problem one level down: it comes from
control_mapper.py::get_actionable_remediation(), a ~35-keyword template table
-- every finding matching a given keyword (e.g. every "telnet" finding) gets
the identical developer-facing template text. Neither is a mitigation step
grounded in what was actually found; both are placeholders.

Called ONLY when the auditor opts in (ai_recommendations=True on the request).
The parser path stays exactly as fast and exactly as deterministic as it is
today -- and stays advertised that way -- unless this is explicitly switched on,
because turning every "instant, zero AI compute" scan into an LLM-backed one by
default would be the opposite of what that mode promises.

Failure mode is fixed at the top: any exception, timeout, or malformed response
anywhere in this module means the ORIGINAL parser-generated remediation is kept
untouched. This function is never allowed to make a finding worse by running.
"""
import json
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

# Findings per LLM call. This was 8, which on a CPU-only box produces ~2000
# output tokens per call -- roughly 15 minutes at the ~1.7 tok/s a 12B model
# manages here, against query_llm()'s default budget of max(600, active*180)
# seconds. Batches therefore ran out of time, and because a failed batch keeps
# its parser text silently, the whole feature looked exactly like leaving it
# switched off: measured 22/22 byte-identical recommendations across an AI-on
# and an AI-off scan of the same evidence. Four keeps each generation short
# enough to finish inside the budget.
_BATCH_SIZE = int(os.environ.get("REMEDIATION_BATCH_SIZE", "4"))

# Explicit budget for enrichment rather than inheriting query_llm()'s default,
# which is tuned for the ISO generator's much shorter completions. This path
# writes several paragraphs per call and legitimately needs longer; the scan
# already runs in the background, so waiting is cheap -- silently dropping the
# text the auditor asked for is not.
_ENRICH_TIMEOUT = int(os.environ.get("REMEDIATION_TIMEOUT_SEC", "1800"))
_ENRICH_TIMEOUT_MAX = int(os.environ.get("REMEDIATION_TIMEOUT_MAX_SEC", "3600"))
_MAX_EVIDENCE_CHARS = 400
_MAX_DESCRIPTION_CHARS = 400

# How many batches run at once. query_llm() already serializes through
# port_pool_manager's per-port semaphore and relies on llama-server's own
# --cont-batching / -np slots to actually execute concurrent requests -- the
# same mechanism concurrent audits already use elsewhere in this app (see
# port_pool.py: "generous limit here -- llama-server queues excess requests
# internally"). Batches used to run one at a time in a plain for-loop, which on
# a large VAPT/PQC scan (hundreds of findings) left every CPU slot beyond the
# first sitting idle while batches queued up sequentially. 4 is deliberately
# modest rather than matching a specific slot count exactly: llama-server's own
# queue absorbs the mismatch safely either way, so there is no correctness
# reason to tune this precisely to the deployment's hardware.
_MAX_PARALLEL_BATCHES = 4

_PROMPT_TEMPLATE = """You are a senior penetration tester writing a vulnerability
report. You will be given {n} findings, each with its title, severity, CVE(s)
if any, and the raw evidence that was actually observed.

For EACH finding, write TWO things. Both must be grounded in what is actually
shown for THAT finding: name the specific service, port, package, or
configuration value that appears in its own evidence, not a generic
instruction that would apply to any finding of that type.
  1. "remediation" -- the recommended fix, for an auditor/report reader, 1 to
     3 sentences.
  2. "actionable" -- concrete, developer-facing steps to implement that fix:
     specific commands, config keys/values, the package or version to upgrade
     to, or the service to disable/restart. 1 to 4 sentences.

RULES, followed exactly:
  - Do not invent a CVE, version number, or fact that is not present in the
    finding's own evidence or title. If the evidence does not say which
    software is running, say to identify the service first rather than
    guessing a product name.
  - Do not change or restate the severity -- you are writing remediation only.
  - If a finding's evidence is too sparse to say anything specific, write
    GENERAL hardening guidance for the affected port/service class named in
    the title, and say plainly that the specific software could not be
    identified from the evidence provided. Do not fabricate specificity that
    is not there.
  - Output ONLY a JSON object, no other text, in exactly this shape:
    {{"remediations": {{"0": {{"remediation": "...", "actionable": "..."}}, ...}}}}
    keyed by the finding's index below, as a string.

FINDINGS:
{findings_block}
"""


def _clip(text, limit):
    text = str(text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "…"


def _format_finding_block(idx: int, f: Dict) -> str:
    cve_list = f.get("cve_list") or []
    cves = ", ".join(cve_list) if cve_list else "none"
    return (
        f"[{idx}] Title: {f.get('title', '')}\n"
        f"    Severity: {f.get('severity', '')}   CVE(s): {cves}   Target: {f.get('target') or 'n/a'}\n"
        f"    Evidence: {_clip(f.get('evidence', ''), _MAX_EVIDENCE_CHARS)}\n"
        f"    Description: {_clip(f.get('description', ''), _MAX_DESCRIPTION_CHARS)}"
    )


def _extract_json_object(raw: str):
    """Same tolerance the ISO chain already applies to LLM output: strip a
    ```json fence if present, otherwise take the outermost {...}. A local model
    under load is not guaranteed to skip the fence even when told to."""
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty response")
    fenced = re.findall(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if fenced:
        text = fenced[0]
    if not (text.startswith("{") and text.endswith("}")):
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("no JSON object found in response")
        text = text[start:end + 1]
    return json.loads(text)


def _enrich_budget() -> int:
    """Enrichment budget: our floor, but still scaling with concurrent load.

    query_llm()'s own default is max(600, active*180). Replacing it with a flat
    number fixed the single-scan case and quietly made the busy case worse --
    generation is slowest exactly when many audits share the CPU, which is when
    the scaling mattered. So keep the scaling and only raise the floor.
    """
    try:
        from src.core.redis_metrics import get_live_metrics
        m = get_live_metrics()
        if m.get("redis_available"):
            active = max(1, len(m.get("active_sessions", [])))
        else:
            from src.core.bg_state import _bg_running
            active = max(1, len(_bg_running))
    except Exception:
        active = 1
    # Ceiling, because the load signal cannot be trusted: the Redis
    # active-sessions set accumulates entries that are never cleared (measured
    # 422 "active" while nothing at all was running), which turns a scaling
    # budget into a ~21-hour one -- long enough that a genuinely hung request
    # never fails and the scan simply never ends. Scale, but not past an hour.
    return max(_ENRICH_TIMEOUT, min(active * 180, _ENRICH_TIMEOUT_MAX))


def _enrich_batch(batch: List[Dict], model: str, session_id=None, timeout=None) -> bool:
    """Mutates `.remediation` on the findings in `batch` in place. Never raises
    -- a batch that fails for any reason is left with its original text, and
    the caller moves on to the next batch rather than aborting the run."""
    from src.core.llm_client import query_llm

    findings_block = "\n".join(_format_finding_block(i, f) for i, f in enumerate(batch))
    prompt = _PROMPT_TEMPLATE.format(n=len(batch), findings_block=findings_block)

    try:
        raw = query_llm(
            prompt, model, num_ctx=8192, temperature=0.1,
            timeout=timeout if timeout is not None else _enrich_budget(),
            session_id=session_id,
            # query_llm()'s DEFAULT stop list includes "```", tuned for the
            # ISO/VAPT XML-tag generator chains where a fence never appears in
            # a valid response. Here the model is EXPECTED to wrap its answer
            # in a ```json fence (the prompt asks for JSON, and this model's
            # chat template opens every reply with a `<|channel>thought`
            # header before its real content) -- so the default list matched
            # the model's own opening fence and truncated the response to
            # nothing, every single time, regardless of format= or timeout.
            # Confirmed by direct comparison: identical prompt, same model,
            # only this stop list changed -- 28-char empty response became a
            # complete, grounded answer. format="json" (grammar-constrained
            # decoding) is intentionally NOT used either: it showed the same
            # empty-response failure, and the prompt instruction plus
            # _extract_json_object's tolerant fence-stripping is sufficient.
            stop=["<end_of_turn>", "<eos>", "<|im_end|>", "</s>"],
        )
        data = _extract_json_object(raw)
        remediations = data.get("remediations")
        if not isinstance(remediations, dict):
            raise ValueError("response missing a 'remediations' object")
    except Exception as e:
        print(f"[REMEDIATION LLM] Batch of {len(batch)} finding(s) not enriched, "
              f"keeping parser text: {type(e).__name__}: {e}", flush=True)
        return False

    for i, f in enumerate(batch):
        entry = remediations.get(str(i))
        # Tolerate a bare string too (some models flatten the nested object
        # despite the prompt) -- treated as "remediation" only, since that was
        # the original single-field contract and is the more important half.
        if isinstance(entry, dict):
            rem_text = str(entry.get("remediation") or "").strip()
            act_text = str(entry.get("actionable") or "").strip()
        else:
            rem_text = str(entry or "").strip()
            act_text = ""
        # A blank or suspiciously short reply is treated as a failure for that
        # ONE field on that ONE finding, not the whole batch -- the other
        # findings (and the other field on this same finding) may well be
        # fine, and the fallback stays the original deterministic text either
        # way, so there is nothing to lose by trying.
        if len(rem_text) >= 15:
            f["remediation"] = rem_text
        if len(act_text) >= 15:
            f["remediation_actionable"] = act_text

    return True


def _vuln_type_key(f: Dict) -> str:
    """Groups findings by VULNERABILITY TYPE, deliberately ignoring host/target
    -- the opposite of Finding.dedup_key() (finding_schema.py), which is
    host-aware on purpose so the same issue on two different servers stays two
    separate report rows. That is correct for the report; it is wasteful for
    THIS module. The remediation sentence for "TLS 1.0 enabled" is the same
    text whether it is host A or host B -- asking the LLM to write it once per
    host is N calls for one answer. Grouping here (LLM cost only; the report
    still lists every host's own finding row untouched) asks it once per
    distinct vulnerability instead.

    Same fallback order as dedup_key(), minus the target component: CVE list,
    then tool+plugin, then tool+normalized title.
    """
    cve_list = f.get("cve_list") or []
    clean_cves = sorted(set(str(c).strip().upper() for c in cve_list if c and str(c).strip()))
    if clean_cves:
        return "cve:" + ":".join(clean_cves)
    tool = str(f.get("source_tool") or "generic").lower().strip()
    plugin_id = str(f.get("plugin_id") or "").strip()
    if plugin_id:
        return f"{tool}:plugin:{plugin_id}"
    title = re.sub(r"\s+", " ", str(f.get("title") or "").strip().lower())
    return f"{tool}:title:{title}"


def enrich_remediations(findings: List[Dict], model: str = "gemma4:e4b",
                        session_id=None, timeout=None, progress_cb=None) -> List[Dict]:
    """Rewrite the "remediation" and "remediation_actionable" keys on each
    finding dict using the LLM, grounded in that finding's own evidence.
    Returns the same list, mutated in place, so callers that already hold a
    reference (bg_worker.py's all_findings) see the change without needing to
    reassign anything.

    Every other key -- severity, cve_list, control_id, title, evidence,
    dedup_key -- is read-only here and is never written to.

    Two things changed from a plain "batch through every finding" loop:

    1. Findings are grouped by _vuln_type_key() first, and only ONE finding
       per group (the LLM COST unit) is actually sent for enrichment; every
       other member of that group gets the same result copied onto it
       afterward. A large scan with the same handful of vulnerabilities
       repeated across many hosts collapses from hundreds of LLM calls to a
       few dozen, with no change to wording quality -- the text really is the
       same advice either way.
    2. The resulting batches run several AT ONCE instead of one after another
       -- see _MAX_PARALLEL_BATCHES.

    Neither optimization changes what gets asked or how it gets judged; a scan
    where every finding is a genuinely distinct vulnerability (no repeats)
    still pays for every one of them, exactly as before.
    """
    if not findings:
        return findings

    groups: Dict[str, List[Dict]] = {}
    order: List[str] = []
    for f in findings:
        key = _vuln_type_key(f)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    representatives = [groups[key][0] for key in order]
    if len(representatives) < len(findings):
        print(f"[REMEDIATION LLM] {len(findings)} finding(s) collapsed to "
              f"{len(representatives)} unique vulnerability type(s) for enrichment "
              f"({len(findings) - len(representatives)} duplicate host instance(s) "
              f"will reuse the same text).", flush=True)

    batches = [representatives[i:i + _BATCH_SIZE] for i in range(0, len(representatives), _BATCH_SIZE)]
    # Count what actually landed. A failed batch keeps its parser text, which is a
    # valid report -- but the auditor asked for AI-tailored text and got the canned
    # version, and nothing anywhere said so. The caller surfaces this.
    _results = []

    def _done(n):
        """Report completed batches. Never let a reporting failure stop the run."""
        if progress_cb:
            try:
                progress_cb(n, len(batches))
            except Exception:
                pass

    if len(batches) > 1:
        # submit/as_completed rather than pool.map: map only yields once every
        # batch has finished, so there is nothing to report until the slowest
        # one lands. Batches still run in parallel exactly as before.
        with ThreadPoolExecutor(max_workers=min(_MAX_PARALLEL_BATCHES, len(batches))) as pool:
            futures = [pool.submit(_enrich_batch, b, model,
                                   session_id=session_id, timeout=timeout)
                       for b in batches]
            for _i, _f in enumerate(as_completed(futures), start=1):
                try:
                    _results.append(bool(_f.result()))
                except Exception:
                    _results.append(False)   # keeps its parser-generated text
                _done(_i)
    elif batches:
        _results = [_enrich_batch(batches[0], model, session_id=session_id, timeout=timeout)]
        _done(1)

    _failed = sum(1 for r in _results if not r)
    if _failed:
        print(f"[REMEDIATION LLM] {_failed}/{len(batches)} batch(es) failed -- those "
              f"finding(s) keep their parser-generated text.", flush=True)
    enrich_remediations.last_failed_batches = _failed
    enrich_remediations.last_total_batches = len(batches)

    # Copy each representative's (possibly still-original, if enrichment
    # failed for that batch) text onto every other member of its group.
    for key in order:
        members = groups[key]
        rep = members[0]
        for dup in members[1:]:
            dup["remediation"] = rep.get("remediation", dup.get("remediation"))
            dup["remediation_actionable"] = rep.get("remediation_actionable", dup.get("remediation_actionable"))

    return findings
