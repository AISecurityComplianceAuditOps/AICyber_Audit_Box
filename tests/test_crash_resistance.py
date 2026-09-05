# -*- coding: utf-8 -*-
"""
Crash resistance -- the software must degrade, never take the process or the
audit down.

    pytest tests/test_crash_resistance.py -v

WHY THIS EXISTS

Every other test in this suite feeds well-formed input. Real evidence is not
well-formed: OCR'd screenshots and raw scanner output carry control bytes,
informational findings have a null severity, and control_id arrives from the LLM,
the DB and Excel rows without a guaranteed type.

Three real crashes were found by testing with deliberately broken input, all of
which had shipped:

  * python-docx raises ValueError on a single control character and aborts the
    WHOLE document -- one bad byte in one finding out of ninety and the auditor
    gets no report at all.
  * A None severity made `"1" in sev` raise and took the entire PDF export down.
    The same flawed line existed in THREE separate places in that file.
  * A non-string control_id made .split() raise inside validate_only, killing the
    audit for that control.

The rule these tests encode: a bad value costs you that value, never the run and
never the document.
"""
import io

import pytest

# ── 1. Hostile / corrupt uploads ─────────────────────────────────────────────
HOSTILE_CONTENT = [
    pytest.param("", id="empty-file"),
    pytest.param((chr(0) + chr(1) + chr(2) + chr(255)) * 500, id="binary-garbage"),
    pytest.param("<?xml version='1.0'?><nmaprun><host><ports>", id="truncated-xml"),
    pytest.param("A" * 200000, id="huge-single-line"),
    pytest.param("Nmap scan report" + chr(0) * 2 + " for 10.0.0.1", id="null-bytes"),
    pytest.param("スキャン \U0001f3af ‮ report", id="unicode-chaos"),
    pytest.param("<div>" * 5000, id="deeply-nested-html"),
]


@pytest.mark.parametrize("content", HOSTILE_CONTENT)
def test_parsers_survive_hostile_uploads(content):
    """A file a customer actually uploaded must never crash the dispatch."""
    from src.core.parsers import parse_tool_file
    parse_tool_file("evidence.txt", content, framework="vapt")


# ── 2. Validator with structurally broken findings ───────────────────────────
BROKEN_FINDINGS = [
    pytest.param({}, id="empty-dict"),
    pytest.param({"control_id": None, "status": None, "evidence_snippet": None}, id="none-values"),
    # The regression: control_id is not guaranteed to be a string.
    pytest.param({"control_id": 123, "status": ["x"], "policy_items_json": "not-json"}, id="wrong-types"),
    pytest.param({"control_id": "5.1", "policy_items_json": "{[bad", "evidence_items_json": "]]]"},
                 id="malformed-json-fields"),
]


@pytest.mark.parametrize("finding", BROKEN_FINDINGS)
def test_validator_survives_broken_findings(finding):
    """One malformed finding must cost that finding, not the whole audit."""
    from src.core.validator import post_process
    post_process(dict(finding), "", {}, db_chunks=[])


# ── 3. LLM unavailable or misbehaving ────────────────────────────────────────
@pytest.mark.parametrize("failure", [
    pytest.param(ConnectionError("connection refused"), id="server-down"),
    pytest.param(TimeoutError("timed out"), id="timeout"),
    pytest.param(None, id="garbage-response"),
])
def test_llm_failure_preserves_parser_text(failure):
    """An LLM failure must leave the deterministic text exactly as it was."""
    from unittest import mock
    from src.core.parsers.remediation_llm import enrich_remediations

    findings = [{"title": "T", "severity": "HIGH", "cve_list": [], "target": "h",
                 "evidence": "e", "description": "d", "remediation": "ORIGINAL",
                 "remediation_actionable": "ORIGINAL_ACTIONABLE"}]
    with mock.patch("src.core.llm_client.query_llm",
                    side_effect=failure,
                    return_value=(None if failure else "!!! not json !!!")):
        enrich_remediations(findings, model="m", timeout=1)

    assert findings[0]["remediation"] == "ORIGINAL"
    assert findings[0]["remediation_actionable"] == "ORIGINAL_ACTIONABLE"


@pytest.mark.parametrize("failure", [
    pytest.param(ConnectionError("connection refused"), id="server-down"),
    pytest.param(TimeoutError("timed out"), id="timeout"),
])
def test_report_narrative_returns_none_rather_than_raising(failure):
    """A failed narrative means the report keeps its standard wording."""
    from unittest import mock
    from src.core.parsers.report_narrative_llm import generate_report_narrative

    findings = [{"title": "T", "severity": "HIGH", "target": "h"}]
    with mock.patch("src.core.llm_client.query_llm", side_effect=failure):
        assert generate_report_narrative(findings, model="m", timeout=1) is None


# ── 4. Report export with broken findings ────────────────────────────────────
EXPORT_BREAKERS = [
    pytest.param([], id="no-findings"),
    # The regression: a null severity aborted the entire PDF.
    pytest.param([{"control_id": None, "title": None, "severity": None}], id="none-fields"),
    pytest.param([{"control_id": 5, "severity": ["HIGH"], "cve_list": "not-a-list"}], id="wrong-types"),
    # The regression: python-docx refuses control characters and aborts the document.
    pytest.param([{"control_id": "5.1", "severity": "HIGH",
                   "finding": "bad " + chr(0) + chr(1) + " text"}], id="control-characters"),
]


@pytest.mark.parametrize("findings", EXPORT_BREAKERS)
def test_docx_export_survives(findings):
    """One bad finding must never cost the auditor the whole document."""
    from src.core.report_exporter import export_docx_report
    out = export_docx_report("T", findings, [], "FINAL")
    assert isinstance(out, (bytes, bytearray)) and len(out) > 0


@pytest.mark.parametrize("findings", EXPORT_BREAKERS)
def test_pdf_export_survives(findings):
    from src.core.report_exporter import export_pdf_report
    out = export_pdf_report("T", findings, [], "FINAL")
    assert isinstance(out, (bytes, bytearray)) and len(out) > 0


def test_xml_safe_strips_only_illegal_characters():
    """Newlines and tabs are legal XML and must survive -- only the bytes
    python-docx rejects are removed."""
    from src.core.report_exporter import xml_safe
    assert xml_safe("clean text") == "clean text"
    assert xml_safe("line1\nline2\tcol") == "line1\nline2\tcol"
    assert chr(0) not in xml_safe("bad" + chr(0) + "text")
    assert xml_safe("bad" + chr(0) + "text") == "badtext"
    assert xml_safe(None) == ""


# ── 5. Worker threads cannot escape their own exception handler ──────────────
@pytest.mark.parametrize("worker_name", ["_run_fast_technical_vapt_bg", "_run_ollama_bg"])
def test_background_workers_have_top_level_exception_handling(worker_name):
    """A worker thread that raises kills the audit silently -- there is no caller
    to catch it. Both must wrap their body."""
    import inspect
    from src.core import bg_worker

    src = inspect.getsource(getattr(bg_worker, worker_name))
    lines = src.splitlines()
    has_try = any(l.strip() == "try:" and (len(l) - len(l.lstrip())) <= 4 for l in lines)
    has_except = any(l.strip().startswith("except") and (len(l) - len(l.lstrip())) <= 4 for l in lines)
    assert has_try and has_except, f"{worker_name} has no top-level try/except"
