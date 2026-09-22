# -*- coding: utf-8 -*-
"""A false positive rejected in one VAPT scan must not come back in the next.

    pytest tests/test_vapt_suppression.py -v

WHY THIS EXISTS

Rejecting a false positive in a VAPT session changed nothing about the next scan.
The knowledge loop that learns from rejections is wired into the ISO path only,
and _run_fast_technical_vapt_bg never read auditor feedback, so every re-scan of
the same target reported the same false positive and the auditor dismissed it
again, engagement after engagement.

These tests drive the REAL scan worker on a real .nessus export and the REAL
finding-edit endpoint, against a scratch database, through the whole cycle:

    scan -> reject -> re-scan (carried forward, left out of the report)
         -> restore -> re-scan (reported again)

THE FAILURE THIS MUST NEVER CAUSE

A real vulnerability hidden is worse than a false positive shown. So:

  * matching is on the parser's exact dedup_key, which includes the target -- the
    same issue on another host is never suppressed by this one
  * a finding whose target is a placeholder is never suppressed at all. Findings
    recovered from a screenshot are given the target "Web Application Endpoint",
    so every screenshot XSS on every application shares one key; suppressing on
    it would let one rejection hide all of them
  * a suppressed finding is carried forward, not dropped: still saved, still
    listed, marked with who decided it and when, and restorable in one step
"""
import io
import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import src.api.endpoints.audit as audit_ep
import src.core.bg_worker as worker
import src.core.report_exporter as rx
from src.core import vapt_suppression as supp
from src.db.database import AuditReport, Base, Finding, VaptSuppression


FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "two_host_findings.nessus")
SWEET32 = "SSL Medium Strength Cipher Suites Supported (SWEET32)"
SELF_SIGNED = "SSL Self-Signed Certificate"


# ── a scratch database both halves of the app are pointed at ────────────────

@pytest.fixture
def db(tmp_path, monkeypatch):
    eng = create_engine("sqlite:///" + str(tmp_path / "vapt.db"))
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    monkeypatch.setattr(worker, "SessionLocal", S)
    monkeypatch.setattr(audit_ep, "SessionLocal", S)
    monkeypatch.setattr(audit_ep, "_require_auth",
                        lambda _r: {"username": "lead.auditor", "role": "admin"})
    monkeypatch.setattr(audit_ep, "_assert_session_access", lambda *a, **k: None)
    monkeypatch.setattr(audit_ep, "log_system_event", lambda *a, **k: None)
    return S


def _session(S, sid):
    s = S()
    s.add(AuditReport(session_id=sid, session_title=sid, framework="VAPT"))
    s.commit()
    s.close()


def _scan(S, sid):
    """Run the real VAPT worker on the fixture for one session."""
    _session(S, sid)
    xml = io.open(FIXTURE, encoding="utf-8").read()
    worker._run_fast_technical_vapt_bg(
        sid, [{"name": "scan.nessus", "text": xml}], selected_sls=[],
        framework="VAPT")
    s = S()
    try:
        rep = s.query(AuditReport).filter(AuditReport.session_id == sid).first()
        rows = s.query(Finding).filter(Finding.report_id == rep.id).all()
        return {r.control_name: dict(id=r.id, status=r.status, key=r.dedup_key,
                                     note=r.review_note or "",
                                     verified=bool(r.human_verified))
                for r in rows}
    finally:
        s.close()


def _set_status(fid, status):
    req = audit_ep.UpdateFindingRequest(status=status)
    out = audit_ep.api_update_finding(fid, req, object())
    assert out.get("success") is True, out


def _suppressions(S):
    s = S()
    try:
        return {r.dedup_key: r.status for r in s.query(VaptSuppression).all()}
    finally:
        s.close()


def _report_text(S, sid):
    """Export the session's findings the way the VAPT PDF export does."""
    s = S()
    try:
        rep = s.query(AuditReport).filter(AuditReport.session_id == sid).first()
        findings = [{"control_id": r.control_id, "control_name": r.control_name,
                     "severity": r.severity, "status": r.status,
                     "final_result": r.final_result or "NON_COMPLIANT",
                     "description": r.description, "recommendation": r.recommendation,
                     "evidence_snippet": r.evidence_snippet, "asset_name": "",
                     "port": "", "source_files": r.source_files}
                    for r in s.query(Finding).filter(Finding.report_id == rep.id).all()]
    finally:
        s.close()
    out = rx._export_vapt_pdf(session_title="VAPT Audit Report", findings=findings,
                              resolved_list=[], status="Final", comments="", metadata={})
    data = out.getvalue() if hasattr(out, "getvalue") else out
    try:
        from pypdf import PdfReader
    except ImportError:
        from PyPDF2 import PdfReader
    return " ".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages)


# ── the whole cycle ──────────────────────────────────────────────────────────

def test_the_first_scan_reports_both_findings_with_specific_keys(db):
    first = _scan(db, "sess-1")
    assert SWEET32 in first and SELF_SIGNED in first, list(first)
    for name in (SWEET32, SELF_SIGNED):
        assert first[name]["key"], "%s was saved without a dedup_key" % name
        assert "10.20.30.40" in first[name]["key"], first[name]["key"]
        assert first[name]["status"] != "Rejected"


def test_rejecting_a_finding_records_a_suppression(db):
    first = _scan(db, "sess-1")
    _set_status(first[SELF_SIGNED]["id"], "Rejected")
    assert _suppressions(db) == {first[SELF_SIGNED]["key"]: "Rejected"}


def test_the_rejected_finding_is_carried_forward_on_the_next_scan(db):
    first = _scan(db, "sess-1")
    _set_status(first[SELF_SIGNED]["id"], "Rejected")

    second = _scan(db, "sess-2")
    carried = second[SELF_SIGNED]
    assert carried["status"] == "Rejected", (
        "the false positive the auditor rejected came back as a live finding")
    assert "Carried forward" in carried["note"] and "lead.auditor" in carried["note"], (
        "a carried-forward finding must say who decided it: %r" % carried["note"])
    assert carried["verified"], "a carried decision should not be re-asked"
    # The OTHER finding on the same host is untouched.
    assert second[SWEET32]["status"] != "Rejected"


def test_the_carried_finding_is_left_out_of_the_report(db):
    first = _scan(db, "sess-1")
    _set_status(first[SELF_SIGNED]["id"], "Rejected")
    _scan(db, "sess-2")
    text = _report_text(db, "sess-2")
    # Matched on each finding's own Nessus description: the report prints the
    # description rather than the plugin name, and "SWEET32" appears only in the
    # plugin name -- so searching for it tests the layout, not the exclusion.
    assert "medium strength encryption" in text, (
        "the genuine SWEET32 finding is missing from the report")
    assert "not signed by a recognized" not in text, (
        "the rejected false positive reached the second engagement's report")


def test_restoring_it_clears_the_suppression_and_the_next_scan_reports_it(db):
    first = _scan(db, "sess-1")
    _set_status(first[SELF_SIGNED]["id"], "Rejected")
    second = _scan(db, "sess-2")

    _set_status(second[SELF_SIGNED]["id"], "Non-Compliant")
    assert _suppressions(db) == {}, "restoring the finding left it suppressed"

    third = _scan(db, "sess-3")
    assert third[SELF_SIGNED]["status"] != "Rejected", (
        "a restored finding was still suppressed on the following scan")
    assert "Carried forward" not in third[SELF_SIGNED]["note"]


# ── the safety rules ─────────────────────────────────────────────────────────

def test_the_same_issue_on_another_host_is_not_suppressed():
    key_a = "nessus:57582|target:10.20.30.40:443/tcp (www)"
    key_b = "nessus:57582|target:10.20.30.99:443/tcp (www)"

    class _S(object):
        status = "Rejected"
        decided_by = "x"
        source_session = ""
        created_at = None

    other_host = [{"dedup_key": key_b, "status": "Non-Compliant"}]
    assert supp.apply(other_host, {key_a: _S()}) == 0
    assert other_host[0]["status"] == "Non-Compliant"


@pytest.mark.parametrize("key", [
    "burp suite / visual ocr:visual poc: stored cross-site scripting|target:web application endpoint",
    "nessus:1|target:",
    "nessus:1|target:unknown",
    "",
    None,
])
def test_a_placeholder_target_is_never_suppressible(key):
    """One rejected screenshot XSS must not hide every screenshot XSS."""
    assert not supp.is_suppressible(key), key


def test_a_screenshot_finding_is_not_recorded_even_when_rejected(tmp_path):
    eng = create_engine("sqlite:///" + str(tmp_path / "s.db"))
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    key = ("burp suite / visual ocr:visual poc: stored cross-site scripting"
           "|target:web application endpoint")
    assert supp.record(s, key, "Rejected") is False
    s.commit()
    assert s.query(VaptSuppression).count() == 0


@pytest.mark.parametrize("status", ["Accepted", "Non-Compliant", "Compliant", "Open"])
def test_only_a_thrown_out_status_records_a_suppression(tmp_path, status):
    """Accept confirms a finding; it must never suppress one."""
    eng = create_engine("sqlite:///" + str(tmp_path / "s.db"))
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    assert supp.record(s, "nessus:1|target:10.0.0.1:443/tcp", status) is False


# ── the path it must not touch ───────────────────────────────────────────────

def test_an_iso_session_never_records_a_suppression(db):
    """ISO learns through the knowledge loop; this is VAPT and PQC only."""
    s = db()
    rep = AuditReport(session_id="iso-1", session_title="iso", framework="ISO 27001")
    s.add(rep)
    s.flush()
    f = Finding(report_id=rep.id, control_id="8.17", control_name="Clock",
                status="Non-Compliant", final_result="NON_COMPLIANT",
                dedup_key="generic:clock|target:10.0.0.1", description="d",
                evidence_snippet="e", recommendation="r", severity="P2 High")
    s.add(f)
    s.commit()
    fid = f.id
    s.close()
    _set_status(fid, "Rejected")
    assert _suppressions(db) == {}, "an ISO rejection was recorded as a VAPT suppression"
