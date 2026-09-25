# -*- coding: utf-8 -*-
"""A closed VAPT finding is given no fix steps.

It is fixed, but the card and both reports gave it "Recommended Remediation"
and "Developer Actionable Mitigation Steps" as if work remained -- for the six
closed rows of a real pentest report, MITRE guidance the report never gave.
Now it says no action is required, keeps the report's own advice for
reference, and has no developer steps; AI mode does not write fix text for it
or count it in the executive summary. An open finding is unchanged, and a
closed one reopened in the Modify dialog gets its steps back.

The card also showed, for any VAPT finding the report gave no advice for, the
VAPT control's generic text or ISO wording ("Establish, document, and
implement procedures to satisfy VAPT-5") where the report said something
else. It now shows what the report shows.

The page's own functions are run under Node where it is available.
"""
import io
import json
import os
import re
import shutil
import subprocess

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import src.core.bg_worker as worker
from src.core.report_exporter import _VAPT_CLOSED_NOTE, _vapt_remediation_parts
from src.db.database import AuditReport, Base

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, "src", "api", "static", "app.js")
MITRE = "General guidance from MITRE CWE-319 (Cleartext Transmission of Sensitive Information), not from the report: 1. Encrypt it."


def _f(**kw):
    base = dict(control_id="VAPT-5", title="Cleartext Transmission of Phone Numbers", severity="LOW",
                description="d", target="https://portal.test/", evidence_snippet="proof",
                recommendation="", remediation_actionable=MITRE)
    base.update(kw)
    return base


# -- the reports --------------------------------------------------------------

def test_a_closed_finding_has_no_fix_steps():
    head, text, steps = _vapt_remediation_parts(_f(status="Closed", final_result="CLOSED"))
    assert (head, text, steps) == ("Remediation Status:", _VAPT_CLOSED_NOTE, "")


def test_an_accepted_closed_finding_neither():
    assert _vapt_remediation_parts(_f(status="Accepted", final_result="CLOSED",
                                      recommendation="Use TLS."))[2] == ""


def test_the_reports_own_advice_is_kept_for_reference():
    _h, text, _s = _vapt_remediation_parts(_f(status="Closed", final_result="CLOSED",
                                               recommendation="Use TLS for the OTP API."))
    assert text == _VAPT_CLOSED_NOTE + "\n\nOriginal recommendation (for reference): Use TLS for the OTP API."


def test_an_open_finding_is_as_before():
    head, text, steps = _vapt_remediation_parts(_f(status="Non-Compliant", final_result="NON_COMPLIANT"))
    assert (head, text, steps) == ("Recommendation:", MITRE, "")          # no advice of its own: the guidance
    head, text, steps = _vapt_remediation_parts(_f(status="Non-Compliant", recommendation="Use TLS."))
    assert (head, text, steps) == ("Recommendation:", "Use TLS.", MITRE)
    # Reopened in the Modify dialog: open again, steps again.
    assert _vapt_remediation_parts(_f(status="Non-Compliant", final_result="NON_COMPLIANT",
                                      recommendation="Use TLS."))[2] == MITRE


def _pair():
    return [_f(status="Closed", final_result="CLOSED"),
            _f(control_id="VAPT-4", title="SQL injection", severity="HIGH", status="Non-Compliant",
               final_result="NON_COMPLIANT", recommendation="Use parameterised queries.",
               remediation_actionable="1. Replace string concatenation with bound parameters.")]


def test_the_pdf_gives_the_closed_finding_no_steps():
    from pypdf import PdfReader
    from src.core.report_exporter import export_pdf_report
    out = export_pdf_report("t", _pair(), [], "FINAL", audit_type="vapt")
    flat = re.sub(r"\s+", " ", " ".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(out)).pages))
    assert "General guidance from MITRE CWE-319" not in flat
    assert "Remediation Status: No action required - this finding is closed (remediated)." in flat
    assert flat.count("Developer Actionable Mitigation Steps") == 1           # the open finding's
    assert "Replace string concatenation with bound parameters" in flat


def test_the_docx_gives_the_closed_finding_no_steps():
    from docx import Document
    from src.core.report_exporter import export_docx_report
    d = Document(io.BytesIO(export_docx_report("t", _pair(), [], "FINAL", audit_type="vapt")))
    text = "\n".join(p.text for p in d.paragraphs)
    assert "General guidance from MITRE CWE-319" not in text
    assert "Remediation Status:" in text and _VAPT_CLOSED_NOTE in text
    assert text.count("Developer Actionable Mitigation Steps:") == 1


# -- AI mode ------------------------------------------------------------------

TRACKER = ("Vulnerability,Severity,Host,Description,Recommendation,Status,CVE\n"
           "SQL Injection in login form,Critical,https://portal.test/login,Injectable.,Use parameterised queries.,Open,\n"
           "Missing HSTS header,Low,https://portal.test/,HSTS not set.,,Closed,\n")


def test_ai_mode_writes_no_fix_text_for_a_closed_finding(tmp_path, monkeypatch):
    from src.core.parsers import remediation_llm, report_narrative_llm
    eng = create_engine("sqlite:///" + str(tmp_path / "v.db"))
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    monkeypatch.setattr(worker, "SessionLocal", S)
    seen = {}
    monkeypatch.setattr(remediation_llm, "enrich_remediations",
                        lambda fs, **k: seen.setdefault("enriched", [f["title"] for f in fs]) and fs)
    monkeypatch.setattr(report_narrative_llm, "generate_report_narrative",
                        lambda fs, **k: seen.setdefault("summarised", [f["title"] for f in fs]) and None)
    s = S()
    s.add(AuditReport(session_id="a1", session_title="a1", framework="VAPT"))
    s.commit()
    s.close()
    worker._run_fast_technical_vapt_bg("a1", [{"name": "t.csv", "bytes": TRACKER.encode(), "text": None}],
                                       selected_sls=[], framework="VAPT", ai_recommendations=True)
    assert seen["enriched"] == ["SQL Injection in login form"]
    assert seen["summarised"] == ["SQL Injection in login form"]


# -- the page -----------------------------------------------------------------

def _function(src, name):
    start = src.index(f"function {name}(")
    depth, i = 0, src.index("{", start)
    while True:
        ch = src[i]
        depth += ch == "{"
        depth -= ch == "}"
        i += 1
        if depth == 0:
            return src[start:i]


def _run(expr, framework="VAPT"):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    src = io.open(APP_JS, encoding="utf-8").read()
    note = src[src.index("const VAPT_CLOSED_NOTE"):]
    note = note[:note.index(";") + 1]
    script = "\n".join([f"let findingsSessionFramework = {json.dumps(framework)};", note]
                       + [_function(src, n) for n in ("isVaptOnlySession", "isFindingClosed",
                                                      "isFindingInformational", "vaptRemediationView")])
    script += "\nprocess.stdout.write(JSON.stringify(%s));\n" % expr
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_the_card_shows_what_the_report_shows():
    closed = _run("vaptRemediationView(%s)" % json.dumps(_f(status="Closed", final_result="CLOSED")))
    assert closed == {"closed": True, "text": _VAPT_CLOSED_NOTE, "own": "", "steps": ""}
    open_ = _run("vaptRemediationView(%s)" % json.dumps(_f(status="Non-Compliant")))
    assert (open_["text"], open_["steps"]) == (MITRE, "")
    own = _run("vaptRemediationView(%s)" % json.dumps(_f(status="Non-Compliant", recommendation="Use TLS.")))
    assert (own["text"], own["steps"]) == ("Use TLS.", MITRE)
    none = _run("vaptRemediationView(%s)" % json.dumps(_f(status="Non-Compliant", remediation_actionable="")))
    assert none["text"] == "The scanner gave no remediation for this finding."


def test_the_card_and_the_report_use_the_same_closed_note():
    src = io.open(APP_JS, encoding="utf-8").read()
    assert f'const VAPT_CLOSED_NOTE = "{_VAPT_CLOSED_NOTE}";' in src


def test_the_api_sends_a_vapt_findings_own_recommendation():
    src = io.open(os.path.join(ROOT, "src", "api", "endpoints", "audit.py"), encoding="utf-8").read()
    block = src[src.index("if _vapt_only_api:"):]
    block = block[:block.index("except Exception as _ow_err")]
    assert 'result[-1]["recommendation"] = f.recommendation or ""' in block
