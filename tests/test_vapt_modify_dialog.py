# -*- coding: utf-8 -*-
"""The Modify dialog on a VAPT finding.

A VAPT finding is a vulnerability, never "Compliant", but the dialog offered
Compliant / Non-Compliant and the ISO labels, and none of what the scanner
reported could be corrected. Now its status is Open / Informational / Closed
(the KPI boxes), Closed is in the severity list too, and target, CVSS score
and vector, CVE / CWE, risk category, CIA impact, tool, confidence and the
developer steps are editable. Two faults went with it:

  * the dialog saved a severity as "High (CVSS 7.0-8.9)", which the reports
    count as nothing (they count "HIGH"): a modified finding left the summary;
  * every text field was capped at 5000 characters and the dialog sends them
    all back, so a finding whose (now whole) proof is longer could not be
    saved at all.

"Closed" is the finding's verdict as well as its status, so Accept -- which
keeps the verdict -- leaves it closed, and reopening it in the dialog clears it.
Every other framework's dialog is unchanged.

The page's own functions are run under Node where it is available.
"""
import io
import json
import os
import re
import shutil
import subprocess

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import src.api.endpoints.audit as audit_ep
from src.core.finding_status import derive_final_result, is_compliant_verdict
from src.db.database import AuditReport, Base, Finding

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, "src", "api", "static", "app.js")
INDEX = os.path.join(ROOT, "src", "api", "static", "index.html")


class _Req(object):
    """The endpoint only hands this to the (patched) auth check."""


@pytest.fixture
def db(tmp_path, monkeypatch):
    eng = create_engine("sqlite:///" + str(tmp_path / "t.db"))
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    s = S()
    rep = AuditReport(session_id="v1", session_title="t", framework="VAPT")
    s.add(rep)
    s.flush()
    f = Finding(report_id=rep.id, control_id="VAPT-4", control_name="Reflected XSS",
                status="Non-Compliant", final_result=None, severity="HIGH",
                description="d", evidence_snippet="e", recommendation="r")
    s.add(f)
    s.commit()
    fid = f.id
    s.close()
    monkeypatch.setattr(audit_ep, "_require_auth", lambda _r: {"username": "a", "role": "admin"})
    monkeypatch.setattr(audit_ep, "_assert_session_access", lambda *a, **k: None)
    monkeypatch.setattr(audit_ep, "log_system_event", lambda *a, **k: None)
    monkeypatch.setattr(audit_ep, "SessionLocal", S)
    return S, fid


def _save(fid, **fields):
    req = audit_ep.UpdateFindingRequest(status=fields.pop("status", "Non-Compliant"), **fields)
    out = audit_ep.api_update_finding(fid, req, _Req())
    assert out.get("success") is True, out


def _row(S, fid):
    s = S()
    try:
        return s.query(Finding).filter(Finding.id == fid).first()
    finally:
        s.close()


# -- the server ---------------------------------------------------------------

def test_a_whole_proof_can_be_saved(db):
    S, fid = db
    poc = "[HTTP Response 1]\n" + "line of the response\n" * 1200          # ~25,000 characters
    _save(fid, evidence_snippet=poc, description="x" * 12000)
    assert _row(S, fid).evidence_snippet == poc.strip()


def test_the_scanner_fields_are_saved(db):
    S, fid = db
    _save(fid, target="https://shop.test/search [term parameter]", severity_score="7.4",
          cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", cve_refs="cwe-79; CVE-2021-44228 CWE-79",
          category="Injection", cia_impact="C:LOW | I:LOW | A:NONE", source_tool="Burp Suite",
          confidence="Firm", remediation_actionable="Encode output.")
    f = _row(S, fid)
    assert (f.target, f.severity_score, f.cvss_vector) == (
        "https://shop.test/search [term parameter]", 7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert f.cve_refs == "CWE-79, CVE-2021-44228"                  # upper-cased, de-duplicated
    assert (f.category, f.cia_impact, f.source_tool, f.confidence, f.remediation_actionable) == (
        "Injection", "C:LOW | I:LOW | A:NONE", "Burp Suite", "Firm", "Encode output.")


def test_empty_clears_a_field_and_a_vector_gives_the_score(db):
    S, fid = db
    _save(fid, target="host", severity_score="9.0", cve_refs="CVE-2021-44228")
    _save(fid, target="", severity_score="", cve_refs="",
          cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    f = _row(S, fid)
    assert (f.target, f.cve_refs) == (None, None)
    assert f.severity_score == 9.8                                 # FIRST's formula for that vector


@pytest.mark.parametrize("field,value", [
    ("cve_refs", "CVE-2021-44228, log4shell"),
    ("cve_refs", "CVE-21-1"),
    ("severity_score", "11"),
    ("severity_score", "high"),
    ("cvss_vector", "x" * 201),
])
def test_bad_scanner_values_are_refused(field, value):
    with pytest.raises(ValidationError):
        audit_ep.UpdateFindingRequest(status="Non-Compliant", **{field: value})


def test_closed_survives_accept_and_reopening_clears_it(db):
    S, fid = db
    _save(fid, status="Closed")                                     # severity not sent: kept
    f = _row(S, fid)
    assert (f.status, f.final_result, f.severity) == ("Closed", "CLOSED", "HIGH")
    _save(fid, status="Accepted")
    assert (_row(S, fid).status, _row(S, fid).final_result) == ("Accepted", "CLOSED")
    _save(fid, status="Non-Compliant", severity="HIGH")             # reopened in the dialog
    assert _row(S, fid).final_result == "NON_COMPLIANT"


def test_closed_is_not_a_pass_and_iso_statuses_are_unchanged():
    assert derive_final_result("Closed") == "CLOSED"
    assert not is_compliant_verdict("Closed", "CLOSED")
    assert not is_compliant_verdict("Accepted", "CLOSED")
    assert derive_final_result("Compliant") == "COMPLIANT"
    assert derive_final_result("Non-Compliant", "COMPLIANT") == "NON_COMPLIANT"
    assert derive_final_result("Accepted", "NON_COMPLIANT") == "NON_COMPLIANT"
    assert derive_final_result("Rejected", "COMPLIANT") == "COMPLIANT"


# -- the reports --------------------------------------------------------------

def _findings():
    base = {"description": "d", "recommendation": "r", "target": "https://shop.test/",
            "evidence_snippet": "proof", "final_result": "NON_COMPLIANT"}
    # Severities as the old dialog saved them.
    return [dict(base, control_id="VAPT-1", title="A", severity="High (CVSS 7.0-8.9)", status="Non-Compliant"),
            dict(base, control_id="VAPT-2", title="B", severity="Critical (CVSS 9.0-10.0)", status="Accepted"),
            dict(base, control_id="VAPT-3", title="C", severity="Informational (CVSS 0.0)", status="Informational")]


def test_a_severity_the_old_dialog_saved_is_counted_in_the_reports():
    from docx import Document
    from pypdf import PdfReader
    from src.core.report_exporter import export_docx_report, export_pdf_report
    d = Document(io.BytesIO(export_docx_report("t", _findings(), [], "FINAL", audit_type="vapt")))
    rows = [[c.text.strip() for c in r.cells] for t in d.tables for r in t.rows]
    i = rows.index(["Critical", "High", "Medium", "Low", "Informational", "Open", "Closed", "Total Findings"])
    assert rows[i + 1] == ["1", "1", "0", "0", "1", "3", "0", "3"]
    pdf = PdfReader(io.BytesIO(export_pdf_report("t", _findings(), [], "FINAL", audit_type="vapt")))
    flat = re.sub(r"\s+", " ", " ".join(p.extract_text() or "" for p in pdf.pages))
    assert "Total Findings 1 1 0 0 1 3 0 3" in flat


# -- the page -----------------------------------------------------------------

def _src():
    return io.open(APP_JS, encoding="utf-8").read()


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
    src = _src()
    names = ("vaptSeverityWord", "vaptDialogState", "vaptDialogSave", "isVaptOnlySession",
             "isFindingClosed", "statusBeforeReview", "deriveFinalResult")
    consts = "\n".join(src[src.index(c):src.index(";", src.index(c)) + 1]
                       for c in ("const _ACCEPTING_STATUSES", "const _AFFIRMING_STATUSES",
                                 "const _WORKFLOW_ONLY_STATUSES"))
    script = "\n".join([f"let findingsSessionFramework = {json.dumps(framework)};", consts]
                       + [_function(src, n) for n in names])
    script += "\nprocess.stdout.write(JSON.stringify(%s));\n" % expr
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.parametrize("finding,state", [
    ({"status": "Non-Compliant", "severity": "HIGH"}, {"status": "Non-Compliant", "severity": "HIGH"}),
    ({"status": "Non-Compliant", "severity": "High (CVSS 7.0-8.9)"}, {"status": "Non-Compliant", "severity": "HIGH"}),
    ({"status": "Closed", "severity": "LOW", "final_result": "CLOSED"}, {"status": "Closed", "severity": "CLOSED"}),
    ({"status": "Accepted", "severity": "LOW", "final_result": "CLOSED"}, {"status": "Closed", "severity": "CLOSED"}),
    ({"status": "Informational", "severity": "INFO"}, {"status": "Informational", "severity": "INFO"}),
    ({"status": "Non-Compliant", "severity": "N/A"}, {"status": "Non-Compliant", "severity": ""}),
])
def test_the_dialog_opens_on_the_findings_own_state(finding, state):
    assert _run("vaptDialogState(%s)" % json.dumps(finding)) == state


@pytest.mark.parametrize("args,saved", [
    (["Non-Compliant", "MEDIUM", "HIGH"], {"status": "Non-Compliant", "severity": "MEDIUM"}),
    (["Closed", "CLOSED", "LOW"], {"status": "Closed", "severity": "LOW"}),          # keeps its severity
    (["Non-Compliant", "CLOSED", "High (CVSS 7.0-8.9)"], {"status": "Closed", "severity": "HIGH"}),
    (["Closed", "CLOSED", ""], {"status": "Closed", "severity": None}),             # none: leave it
    (["Informational", "INFO", "HIGH"], {"status": "Informational", "severity": "INFO"}),
    (["Non-Compliant", "", "N/A"], {"status": "Non-Compliant", "severity": ""}),    # must choose one
])
def test_the_dialog_saves_plain_values(args, saved):
    assert _run("vaptDialogSave(%s)" % ", ".join(json.dumps(a) for a in args)) == saved


def test_closed_on_the_page_follows_the_verdict():
    got = _run("""[
        isFindingClosed({status: "Accepted", final_result: "CLOSED"}),
        isFindingClosed({status: "Accepted", final_result: "NON_COMPLIANT",
                         evidence_snippet: "Status in report: Closed / remediated"}),
        statusBeforeReview({status: "Accepted", final_result: "CLOSED", severity: "LOW"}),
        deriveFinalResult("Closed", "NON_COMPLIANT"),
        deriveFinalResult("Accepted", "CLOSED")]""")
    assert got == [True, False, "Closed", "CLOSED", "CLOSED"]
    assert _run('isFindingClosed({status: "Closed", final_result: "CLOSED"})', framework="ISO 27001") is False


def test_the_vapt_lists_have_no_compliant_and_offer_closed():
    src = _src()
    status = src[src.index("const _VAPT_STATUS_OPTIONS"):src.index("];", src.index("const _VAPT_STATUS_OPTIONS"))]
    sev = src[src.index("const _VAPT_SEVERITY_OPTIONS"):src.index("];", src.index("const _VAPT_SEVERITY_OPTIONS"))]
    assert re.findall(r'\["([^"]+)"', status) == ["Non-Compliant", "Informational", "Closed"]
    assert re.findall(r'\["([^"]+)"', sev) == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "CLOSED"]
    assert "Compliant\"" not in status.replace("Non-Compliant", "")


def test_other_frameworks_keep_their_dialog():
    html = io.open(INDEX, encoding="utf-8").read()
    select = html[html.index('<select id="edit-finding-status">'):]
    select = select[:select.index("</select>")]
    assert '<option value="Compliant">Compliant</option>' in select
    assert '<option value="Non-Compliant">Non-Compliant</option>' in select
    assert 'id="edit-vapt-fields" style="display:none;"' in html      # hidden unless VAPT
    open_fn = _function(_src(), "openEditFindingModal")
    assert "_setEditDialogMode(_vaptMode, statusSelect)" in open_fn
    assert "if (!_vaptMode) _applyModifyStatusOptions(statusSelect, targetStatusVal);" in open_fn
