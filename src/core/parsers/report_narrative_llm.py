# -*- coding: utf-8 -*-
"""
Scan-level narrative for VAPT/PQC reports -- the executive summary and the
tactical recommendations, written from what this scan actually found.

WHY THIS EXISTS

Two blocks in the VAPT report are the same words on every scan, whatever was
found. report_exporter.py's section 2.2 "Analysis Overview" is a fixed paragraph
about the objective of vulnerability assessment, and section 2.4 "Tactical
Recommendations" is one hardcoded sentence:

    "It is recommended to follow the guidelines suggested by OWASP, OSSTMM and
     NIST. It is recommended to implement secure SDLC while developing the
     application."

A client reads the executive summary first, and today it tells them nothing about
their own scan -- identical text whether the scan found three informational
notices or an unauthenticated RCE.

WHAT THIS DOES NOT TOUCH

Severity, CVSS score, CVE list, counts, host list, CWE/OWASP mapping. Those come
from the scanners and stay deterministic, because they are the numbers an auditor
has to defend. Only the prose around them is written here, from a summary of
those same deterministic facts.

Called ONLY when the auditor opts in (ai_recommendations=True), so the VAPT path
keeps its "no LLM" guarantee by default. Any failure returns None and the caller
keeps the existing static text -- this can never leave a report section empty.
"""
import json
import re
from typing import Dict, List, Optional

_MAX_TITLES = 25          # enough for the model to see the shape of the scan
_MAX_TITLE_CHARS = 110


def _clip(text, limit):
    text = str(text or "").strip()
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def summarise_findings(findings: List[Dict]) -> Dict:
    """Deterministic facts about the scan. Computed here, never asked of the LLM."""
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    hosts, cves, tools, titles = set(), set(), set(), []
    # PQC-specific: the quantum readiness split and which algorithms were seen.
    quantum_counts = {"VULNERABLE": 0, "WEAK": 0, "SAFE": 0}
    algorithms, asset_categories = set(), set()

    for f in findings or []:
        sev = str(f.get("severity") or "").strip().upper()
        for key in sev_counts:
            if sev.startswith(key[:4]):
                sev_counts[key] += 1
                break
        for h in str(f.get("target") or f.get("host") or "").replace(",", " ").split():
            h = h.strip()
            if h and h.lower() not in ("n/a", "none", "unknown"):
                hosts.add(h)
        for c in (f.get("cve_list") or []):
            cves.add(str(c))
        if f.get("source_tool"):
            tools.add(str(f["source_tool"]))
        if len(titles) < _MAX_TITLES and f.get("title"):
            titles.append(f"{sev or 'UNKNOWN'}: {_clip(f['title'], _MAX_TITLE_CHARS)}")

        qs = str(f.get("quantum_status") or "").strip().upper()
        if qs in quantum_counts:
            quantum_counts[qs] += 1
        if f.get("algorithm"):
            algorithms.add(str(f["algorithm"]))
        if f.get("asset_category"):
            asset_categories.add(str(f["asset_category"]))

    return {
        "total": len(findings or []),
        "severity_counts": sev_counts,
        "hosts": sorted(hosts),
        "cves": sorted(cves),
        "tools": sorted(tools),
        "titles": titles,
        "quantum_counts": quantum_counts,
        "algorithms": sorted(algorithms),
        "asset_categories": sorted(asset_categories),
        # True when the findings carry quantum readiness data at all -- decides
        # which report this narrative is being written for.
        "is_pqc": any(quantum_counts.values()) or bool(algorithms),
    }


_PQC_PROMPT = """You are a cryptography consultant writing the executive summary of a
Post-Quantum Cryptography (PQC) Readiness Assessment for a client's management.

These are the VERIFIED facts of this assessment. They come from the deterministic
PQC parser and are already correct -- use them, do not recompute them, and do not
contradict them:

Total findings: {total}
Quantum readiness: {q_vulnerable} quantum-vulnerable, {q_weak} classically weak, {q_safe} quantum-safe
By severity: CRITICAL {critical}, HIGH {high}, MEDIUM {medium}, LOW {low}, INFO {info}
Algorithms observed: {algorithms}
Asset categories: {asset_categories}
Assets in scope: {hosts}

Findings observed:
{titles}

Write TWO things about THIS assessment:

1. "overview" -- 3 to 5 sentences for management. State what was assessed, the
   organisation's quantum readiness posture, and which specific algorithms or asset
   classes carry the most exposure. Reference the "Harvest Now, Decrypt Later" risk
   only where long-lived or externally exposed data is genuinely implicated by the
   findings above.

2. "recommendations" -- 3 to 5 prioritised migration actions for THIS assessment,
   most urgent first, each tracing to a finding listed above. Name the actual
   algorithm and its NIST replacement (FIPS 203 ML-KEM for key exchange, FIPS 204
   ML-DSA for signatures) where the findings support it. Do NOT write generic advice
   like "follow NIST PQC standards" -- that is what this is replacing.

RULES, followed exactly:
  - Do not invent an algorithm, asset, count or standard that is not listed above.
  - Do not restate the counts as a list; write prose.
  - No filler ("It is important to note", "In conclusion"), no closing offer of help.
  - Output ONLY a JSON object, no other text, in exactly this shape:
    {{"overview": "...", "recommendations": "..."}}
"""


_PROMPT = """You are a senior penetration tester writing the executive summary of a
vulnerability assessment report for a client's management.

These are the VERIFIED facts of this scan. They come from the scanners themselves
and are already correct -- use them, do not recompute them, and do not contradict
them:

Total findings: {total}
By severity: CRITICAL {critical}, HIGH {high}, MEDIUM {medium}, LOW {low}, INFO {info}
Hosts in scope: {hosts}
Tools used: {tools}
CVEs identified: {cves}

Findings observed:
{titles}

Write TWO things about THIS scan:

1. "overview" -- 3 to 5 sentences for management. State what was assessed, what the
   overall security posture looks like, and the most serious themes actually present
   in the findings above. Name the real issues. If the scan is clean or only
   informational, say so plainly rather than manufacturing alarm.

2. "recommendations" -- 3 to 5 prioritised, concrete actions for THIS scan, most
   urgent first. Each must trace to a finding listed above. Do NOT write generic
   advice like "follow OWASP guidelines" or "implement secure SDLC" -- that is what
   this is replacing.

RULES, followed exactly:
  - Do not invent a host, CVE, tool, count or vulnerability that is not listed above.
  - Do not restate the severity counts as a list; write prose.
  - No filler ("It is important to note", "In conclusion"), no closing offer of help.
  - Output ONLY a JSON object, no other text, in exactly this shape:
    {{"overview": "...", "recommendations": "..."}}
"""


def _extract_json_object(raw: str):
    """Same tolerance the other chains apply: strip a ```json fence if present,
    otherwise take the outermost {...}."""
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


def generate_report_narrative(findings: List[Dict], model: str = "gemma4:e4b",
                              session_id=None, timeout=None) -> Optional[Dict]:
    """Returns {"overview": str, "recommendations": str} or None.

    None means "keep the existing static text" -- the caller must treat this as a
    normal outcome, not an error. One LLM call per report, not per finding.
    """
    if not findings:
        return None

    facts = summarise_findings(findings)
    sc = facts["severity_counts"]
    qc = facts["quantum_counts"]

    # PQC findings carry a quantum_status the VAPT ones never have, and a PQC report
    # is a migration-readiness document rather than a vulnerability report -- the two
    # need different framing, so the prompt is chosen from the findings themselves
    # rather than from a flag the caller has to remember to pass.
    if facts["is_pqc"]:
        prompt = _PQC_PROMPT.format(
            total=facts["total"],
            q_vulnerable=qc["VULNERABLE"], q_weak=qc["WEAK"], q_safe=qc["SAFE"],
            critical=sc["CRITICAL"], high=sc["HIGH"], medium=sc["MEDIUM"],
            low=sc["LOW"], info=sc["INFO"],
            algorithms=", ".join(facts["algorithms"][:25]) or "not stated",
            asset_categories=", ".join(facts["asset_categories"][:15]) or "not stated",
            hosts=", ".join(facts["hosts"][:20]) or "not stated in the evidence",
            titles="\n".join(f"  - {t}" for t in facts["titles"]) or "  (none)",
        )
    else:
        prompt = _PROMPT.format(
            total=facts["total"],
            critical=sc["CRITICAL"], high=sc["HIGH"], medium=sc["MEDIUM"],
            low=sc["LOW"], info=sc["INFO"],
            hosts=", ".join(facts["hosts"][:20]) or "not stated in the scan output",
            tools=", ".join(facts["tools"]) or "not stated",
            cves=", ".join(facts["cves"][:25]) or "none identified",
            titles="\n".join(f"  - {t}" for t in facts["titles"]) or "  (none)",
        )

    try:
        from src.core.llm_client import query_llm
        raw = query_llm(
            prompt, model, num_ctx=8192, temperature=0.2,
            timeout=timeout, session_id=session_id,
            # Same stop-token reasoning as remediation_llm.py: query_llm's default
            # list includes "```", which matches this model's own opening fence and
            # truncates the whole response to nothing.
            stop=["<end_of_turn>", "<eos>", "<|im_end|>", "</s>"],
        )
        data = _extract_json_object(raw)
        overview = str(data.get("overview") or "").strip()
        recommendations = str(data.get("recommendations") or "").strip()
        # A near-empty reply is a failure, not a summary. The static text it would
        # replace is at least complete.
        if len(overview) < 40 or len(recommendations) < 40:
            raise ValueError("response too short to be a real summary")
        return {"overview": overview, "recommendations": recommendations}
    except Exception as e:
        print(f"[REPORT NARRATIVE] Not generated, keeping the standard text: "
              f"{type(e).__name__}: {e}", flush=True)
        return None
