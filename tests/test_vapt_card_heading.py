# -*- coding: utf-8 -*-
"""A VAPT finding card names its control in full, and the vulnerability under it.

The shared card header joined "VAPT-5 — <vulnerability>" and then split it at
" — " (meant for an ISO control and its audit question), so a VAPT card read
only "VAPT-5": neither the control's name ("Internal Network Penetration Test")
nor the vulnerability ("SQL injection") was anywhere on it. /audit/findings now
sends the control's catalogue name (control_full_name); the VAPT card shows it
as the header and the vulnerability on the line below. ISO and PQC cards are
unchanged. Node is not required: the helpers are mirrored and app.js checked.
"""
import os
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import src.api.endpoints.audit as audit_ep
from src.db.database import AuditReport, Base, Finding

APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "src", "api", "static", "app.js")


@pytest.fixture(scope="module")
def js():
    return open(APP_JS, encoding="utf-8").read()


def _func(js, name):
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}\n", start)]


# -- mirrors of vaptControlHeading / vaptFindingName ---------------------------

_LOC = re.compile(r"\s*\(((?:[a-z][a-z0-9+.-]*://|/)[^()]*)\)\s*$", re.I)


def heading(f, fallback=""):
    cid, full = (f.get("control_id") or "").strip(), (f.get("control_full_name") or "").strip()
    if not full:
        return fallback or cid
    if cid and full.upper().startswith(cid.upper()):
        rest = full[len(cid):].strip()
        return f"{cid} — {rest}" if rest else cid
    return full


def name(f):
    return _LOC.sub("", (f.get("custom_heading") or f.get("control_name") or f.get("title") or "").strip()).strip()


PDF_ROW = {"control_id": "VAPT-5", "control_full_name": "VAPT-5 Internal Network Penetration Test",
           "control_name": "SQL injection (https://ginandjuice.shop/catalog/filter [category parameter])"}


@pytest.mark.parametrize("f, want", [
    (PDF_ROW, "VAPT-5 — Internal Network Penetration Test"),
    ({"control_id": "VAPT-4", "control_full_name": "VAPT-4 Web Application Testing OWASP Top 10"},
     "VAPT-4 — Web Application Testing OWASP Top 10"),
    ({"control_id": "VAPT-5", "control_full_name": ""}, "VAPT-5"),            # an older server
    ({"control_id": "VAPT-5"}, "VAPT-5"),
])
def test_the_heading(f, want):
    assert heading(f, f.get("control_id")) == want


@pytest.mark.parametrize("f, want", [
    (PDF_ROW, "SQL injection"),
    ({"control_name": "Cross-site request forgery"}, "Cross-site request forgery"),
    ({"control_name": "SSL Medium Strength Cipher Suites Supported (SWEET32)"},
     "SSL Medium Strength Cipher Suites Supported (SWEET32)"),             # a name in brackets stays
    ({"control_name": "SQL injection", "custom_heading": "SQLi in the product filter"}, "SQLi in the product filter"),
])
def test_the_vulnerability_name(f, want):
    assert name(f) == want


def test_app_js_has_the_same_helpers(js):
    h = _func(js, "vaptControlHeading")
    assert "f.control_full_name" in h and "`${id} — ${rest}`" in h and "return fallback || id;" in h
    n = _func(js, "vaptFindingName")
    assert "f.custom_heading || f.control_name || f.title" in n and "_VAPT_NAME_LOCATION_RE" in n
    assert ("const _VAPT_NAME_LOCATION_RE = /\\s*\\(((?:[a-z][a-z0-9+.-]*:\\/\\/|\\/)[^()]*)\\)\\s*$/i;" in js)


def test_only_the_vapt_card_changed(js):
    body = js[js.index("function renderFindingsList("):]
    vapt = body[body.index("if (isVapt) {"):body.index("Not a VAPT/PQC finding, so this is the ISO / NIST card.")]
    iso = body[body.index("Not a VAPT/PQC finding, so this is the ISO / NIST card."):]
    assert "const _vHeading = isPqc ? displayHeaderTitle : vaptControlHeading(f, displayHeaderTitle);" in vapt
    assert 'const _vName = isPqc ? "" : vaptFindingName(f);' in vapt
    assert "${escapeHtml(_vHeading)}</h3>" in vapt and "${_vNameHtml}" in vapt
    assert "_vHeading" not in iso[:iso.index("`;")] and "${escapeHtml(displayHeaderTitle)}</h3>" in iso


@pytest.fixture
def api(tmp_path, monkeypatch):
    eng = create_engine("sqlite:///" + str(tmp_path / "heading.db"))
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    monkeypatch.setattr(audit_ep, "SessionLocal", S)
    monkeypatch.setattr(audit_ep, "_require_auth", lambda _r: {"username": "a", "role": "admin"})
    monkeypatch.setattr(audit_ep, "_assert_session_access", lambda *a, **k: None)
    app = FastAPI()
    app.include_router(audit_ep.router, prefix="/api")
    return S, TestClient(app)


def test_the_api_sends_the_full_control_name(api):
    """/audit/findings for a VAPT finding mapped to VAPT-5."""
    S, client = api
    s = S()
    rep = AuditReport(session_id="heading-check", session_title="h", framework="VAPT Framework Controls", created_by="a")
    s.add(rep)
    s.commit()
    s.add(Finding(report_id=rep.id, control_id="VAPT-5", control_name=PDF_ROW["control_name"],
                  severity="HIGH", status="Non-Compliant", final_result="NON_COMPLIANT"))
    s.commit()
    s.close()
    rows = client.get("/api/audit/findings", params={"session_id": "heading-check"}).json()["findings"]
    assert rows[0]["control_full_name"] == "VAPT-5 Internal Network Penetration Test"
    assert rows[0]["control_name"] == PDF_ROW["control_name"]           # unchanged
