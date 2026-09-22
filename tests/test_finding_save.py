# -*- coding: utf-8 -*-
"""Saving a finding must work, and must say so when it does not.

    pytest tests/test_finding_save.py -v

WHY THIS EXISTS

"Save Findings Changes" was reported as a button that did nothing. Two faults,
either of which is enough on its own.

The browser. handleEditFindingSubmit() closed the dialog only when the response
carried success:true, and had no else. The server answers an error with
{"detail": ...} and no success key, so on any failure the check was simply false:
no message, the dialog stayed open, and the auditor's edit had not been saved.

The server. PUT /audit/findings/{id} writes the finding and then a feedback row
for the knowledge loop, in one transaction. Any failure writing that row rolled
back the finding with it and the whole save answered 500. One way that happens
is the schema itself: acaffc4 added AuditorFeedback.final_verdict, and until
reconcile_schemas() has run against a database, that column does not exist --
confirmed on the development database, where the table has no such column. Every
Accept, Reject and Modify then fails on the INSERT, and with the browser saying
nothing, it looks like a dead button.

The learning log is secondary to the thing the auditor asked for. It now sits in
its own SAVEPOINT: it may be lost, the edit may not.
"""
import io
import os
import re

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

import src.api.endpoints.audit as audit_ep
from src.db.database import Base, Finding, AuditReport


APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "src", "api", "static", "app.js")


class _Req(object):
    """The endpoint only hands this to the (patched) auth check."""


def _db(tmp_path, migrated):
    """A SQLite database with the real models, optionally without the column."""
    eng = create_engine("sqlite:///" + str(tmp_path / "t.db"))
    Base.metadata.create_all(eng)
    if not migrated:
        # Rebuild auditor_feedback as it stands on a database that has not been
        # migrated yet: every column except final_verdict.
        with eng.begin() as c:
            c.execute(text("DROP TABLE auditor_feedback"))
            c.execute(text(
                "CREATE TABLE auditor_feedback (id INTEGER PRIMARY KEY, "
                "control_id VARCHAR(100), evidence_snippet TEXT, "
                "corrected_status VARCHAR(50), finding TEXT, recommendation TEXT, "
                "auditor_comments TEXT, created_at TIMESTAMP)"))
    S = sessionmaker(bind=eng)
    s = S()
    rep = AuditReport(session_id="sess-1", session_title="t", framework="VAPT")
    s.add(rep)
    s.flush()
    f = Finding(report_id=rep.id, control_id="VAPT-4", control_name="Stored XSS",
                status="Non-Compliant", final_result="NON_COMPLIANT",
                severity="P2 High", description="d", evidence_snippet="e",
                recommendation="r")
    s.add(f)
    s.commit()
    fid = f.id
    s.close()
    return S, fid


@pytest.fixture
def endpoint(monkeypatch):
    monkeypatch.setattr(audit_ep, "_require_auth", lambda _r: {"username": "a", "role": "admin"})
    monkeypatch.setattr(audit_ep, "_assert_session_access", lambda *a, **k: None)
    monkeypatch.setattr(audit_ep, "log_system_event", lambda *a, **k: None)
    return monkeypatch


def _save(monkeypatch, S, fid, **fields):
    monkeypatch.setattr(audit_ep, "SessionLocal", S)
    req = audit_ep.UpdateFindingRequest(status=fields.pop("status", "Accepted"), **fields)
    return audit_ep.api_update_finding(fid, req, _Req())


def _row(S, fid):
    s = S()
    try:
        f = s.query(Finding).filter(Finding.id == fid).first()
        return f.status, f.final_result, bool(f.human_verified), f.recommendation
    finally:
        s.close()


# ── the server ───────────────────────────────────────────────────────────────

def test_a_save_succeeds_on_a_database_not_yet_migrated(endpoint, tmp_path):
    """The reported failure: no final_verdict column, and the save must land."""
    S, fid = _db(tmp_path, migrated=False)
    out = _save(endpoint, S, fid, status="Accepted",
                recommendation="Encode output in the bio field.")
    assert out.get("success") is True, out
    status, verdict, verified, rec = _row(S, fid)
    assert status == "Accepted"
    assert verdict == "NON_COMPLIANT", "Accept must not have rewritten the verdict"
    assert verified, "the finding was not marked reviewed"
    assert rec == "Encode output in the bio field.", (
        "the auditor's edit was rolled back with the feedback row")


def test_a_save_on_a_migrated_database_still_writes_the_feedback(endpoint, tmp_path):
    """The savepoint must not swallow the log on the healthy path."""
    S, fid = _db(tmp_path, migrated=True)
    out = _save(endpoint, S, fid, status="Accepted")
    assert out.get("success") is True, out
    s = S()
    try:
        rows = s.execute(text(
            "SELECT corrected_status, final_verdict FROM auditor_feedback")).fetchall()
    finally:
        s.close()
    assert rows == [("Accepted", "NON_COMPLIANT")], rows


def test_the_feedback_write_is_isolated_in_a_savepoint():
    src = io.open(audit_ep.__file__, encoding="utf-8").read()
    start = src.index("def api_update_finding(")
    body = src[start:src.index("\n@router.", start)]
    assert "begin_nested()" in body, (
        "the feedback row is back in the finding's own transaction, so a failure "
        "writing it rolls back the auditor's edit")


# ── the browser ──────────────────────────────────────────────────────────────

def test_a_failed_save_is_reported_to_the_auditor():
    src = io.open(APP_JS, encoding="utf-8").read()
    m = re.search(r"async function handleEditFindingSubmit\(e\) \{.*?\n\}", src, re.S)
    assert m, "handleEditFindingSubmit not found"
    body = m.group(0)
    assert "response.ok" in body, "the handler still ignores the HTTP status"
    assert "} else {" in body and "not saved" in body, (
        "a failed save still does nothing -- the dialog stays open with no "
        "message and the edit is silently lost")
