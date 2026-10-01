# -*- coding: utf-8 -*-
"""ISO report rows: Observation is what was found, Impact is the consequence.

The exports read `description` as the observation and `reasoning` as the impact.
Control and Selective findings store "Business Impact: X | Missing Requirements:
Y" in description and the observation narrative in reasoning, so the two columns
came out swapped; on a Checklist row description and reasoning both hold the
answer, so Impact repeated Observation word for word. The audit has always
stored the real impact in `business_impact` (the Checklist prompt asks for one
on a No / Not stated answer); the export endpoints sent `reasoning` instead.

The finding shapes below are the ones the database holds for each mode.
"""
import inspect
import io
import re

import pytest

import src.core.report_exporter as rx

CONTROL = {  # Control (Excel) and Selective store the same shape
    "control_id": "8.13 Information Backup", "control_name": "8.13 Information Backup",
    "status": "NON_COMPLIANT", "final_result": "NON_COMPLIANT", "severity": "P3 Medium",
    "description": ("Business Impact: Failure to verify backup integrity regularly could lead to data loss "
                    "during a disaster recovery event. | Missing Requirements: Backup logs to verify nightly "
                    "success., Evidence of quarterly restore testing (only one test provided)."),
    "reasoning": ("No, the organization has not provided backup logs or a sufficient frequency of restore "
                  "test reports to satisfy the control."),
    "business_impact": ("Failure to verify backup integrity regularly could lead to data loss during a "
                        "disaster recovery event."),
    "recommendation": "Provide backup logs and quarterly restore test reports.",
    "source_files": "Restore_Test_Report.txt",
}
CONTROL["gap_description"] = CONTROL["description"]

CHECKLIST_YES = {
    "control_id": "Q2", "control_name": "Whether NTP is enabled and synchronized?",
    "requirement_question": "Whether NTP is enabled and synchronized?",
    "status": "COMPLIANT", "final_result": "COMPLIANT", "severity": "N/A",
    "description": "Yes, NTP is both enabled and synchronized on demo-server.",
    "gap_description": "Yes, NTP is both enabled and synchronized on demo-server.",
    "reasoning": "Yes, NTP is both enabled and synchronized on demo-server.",
    "business_impact": "", "recommendation": "No action required.", "source_files": "NTP_Status.txt",
}

CHECKLIST_NO = {
    "control_id": "Q3", "control_name": "Is restore testing performed every quarter?",
    "requirement_question": "Is restore testing performed every quarter?",
    "status": "NON_COMPLIANT", "final_result": "NON_COMPLIANT", "severity": "P3 Medium",
    "description": "No, the report records a single restore test on 18 March 2025.",
    "gap_description": "No, the report records a single restore test on 18 March 2025.",
    "reasoning": "No, the report records a single restore test on 18 March 2025.",
    "business_impact": "A failed restore could go unnoticed until data is actually needed.",
    "recommendation": "Run and record a restore test every quarter.", "source_files": "Restore_Test_Report.txt",
}

TIMED_OUT = {
    "control_id": "8.17 Clock Synchronization", "control_name": "8.17 Clock Synchronization",
    "status": "NON_COMPLIANT", "final_result": "NON_COMPLIANT", "severity": "P2 High",
    "description": ("No assessment was produced for 8.17 Clock Synchronization because the model request "
                    "timed out or the LLM server was unreachable."),
    "reasoning": ("No assessment was produced for 8.17 Clock Synchronization because the model request "
                  "timed out or the LLM server was unreachable."),
    "business_impact": ("Unable to determine compliance for 8.17 Clock Synchronization: the AI model did "
                        "not respond before the request timed out."),
    "recommendation": "Re-run this control.", "source_files": "NTP_Status.txt",
}
TIMED_OUT["gap_description"] = TIMED_OUT["description"]

ROWS = [CONTROL, CHECKLIST_YES, CHECKLIST_NO, TIMED_OUT]


# -- the helper ---------------------------------------------------------------

def test_control_and_selective_put_the_observation_under_observations():
    obs, impact = rx._iso_observation_and_impact(dict(CONTROL))
    assert obs.startswith("No, the organization has not provided backup logs")
    assert "Business Impact:" not in obs
    assert obs.endswith("Missing requirements: Backup logs to verify nightly success; "
                        "Evidence of quarterly restore testing (only one test provided).")
    assert impact == CONTROL["business_impact"]


def test_a_compliant_row_has_no_impact():
    obs, impact = rx._iso_observation_and_impact(dict(CHECKLIST_YES))
    assert (obs, impact) == (CHECKLIST_YES["reasoning"], "NIL")


def test_a_checklist_gap_shows_its_stored_impact():
    obs, impact = rx._iso_observation_and_impact(dict(CHECKLIST_NO))
    assert obs == CHECKLIST_NO["reasoning"]
    assert impact == CHECKLIST_NO["business_impact"] != obs


def test_a_timed_out_control_stays_honest_in_both_columns():
    obs, impact = rx._iso_observation_and_impact(dict(TIMED_OUT))
    assert obs.startswith("No assessment was produced")
    assert impact.startswith("Unable to determine compliance") and impact != "NIL"


def test_an_impact_that_repeats_the_observation_is_never_printed():
    """The payload the endpoints used to send: business_impact = reasoning."""
    old = dict(CHECKLIST_NO, business_impact=CHECKLIST_NO["reasoning"])
    obs, impact = rx._iso_observation_and_impact(old)
    assert impact == rx._NO_IMPACT_RECORDED and impact != obs


def test_without_a_stored_impact_the_description_supplies_it():
    """Rows saved before business_impact was stored: the impact is still in description."""
    old = dict(CONTROL, business_impact="")
    _obs, impact = rx._iso_observation_and_impact(old)
    assert impact == CONTROL["business_impact"]


# -- the export endpoints send the stored impact ---------------------------------

def test_both_export_endpoints_send_the_stored_impact_not_reasoning():
    from src.api.endpoints import audit
    src = inspect.getsource(audit)
    assert src.count('"business_impact": getattr(f, "business_impact", None) or ""') >= 3   # list API + 2 exports
    assert '"business_impact": f.reasoning' not in src


# -- the documents ------------------------------------------------------------------

META = {"brand_firm": "Dhiware Technologies Pvt Ltd", "framework": "ISO 27001"}


def _obs_rows_from_docx(data):
    from docx import Document
    doc = Document(io.BytesIO(data))
    table = max(doc.tables, key=lambda t: len(t.columns))
    hdr = [c.text.strip() for c in table.rows[0].cells]
    i_obs = next(i for i, t in enumerate(hdr) if t.startswith("Observation"))
    i_imp = next(i for i, t in enumerate(hdr) if t.startswith("Impact"))
    rows = []
    for row in table.rows[1:]:
        cells = [c.text.strip() for c in row.cells]
        if len(cells) > i_imp and cells[i_obs] and cells[i_imp]:
            rows.append((cells[i_obs], cells[i_imp]))
    return rows


def _check_rows(rows):
    assert len(rows) >= 4, rows
    for obs, imp in rows:
        assert not rx._same_text(imp, obs), ("Impact repeats Observation", obs, imp)
        assert "Business Impact:" not in obs, obs
    text = "\n".join(o + "\n" + i for o, i in rows)
    assert "Failure to verify backup integrity" in text
    assert "A failed restore could go unnoticed" in text
    assert any(imp == "NIL" for _o, imp in rows)


@pytest.mark.parametrize("which", ["template", "fallback"])
def test_word_reports(which, monkeypatch):
    if which == "fallback":
        monkeypatch.setattr(rx, "_export_iso_template_docx", lambda *a, **k: None)
    data = rx.export_docx_report("ISO 27001 Audit", [dict(r) for r in ROWS], [], "Reviewed",
                                 audit_type="iso", metadata=META)
    _check_rows(_obs_rows_from_docx(data))


def test_pdf_report(monkeypatch):
    monkeypatch.setattr(rx, "_docx_bytes_to_pdf", lambda *a, **k: None)   # the built-in PDF layout
    from pypdf import PdfReader
    data = rx.export_pdf_report("ISO 27001 Audit", [dict(r) for r in ROWS], [], "Reviewed",
                                audit_type="iso", metadata=META)
    text = re.sub(r"\s+", " ", " ".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages))
    assert "Business Impact:" not in text
    assert "Failure to verify backup integrity" in text and "A failed restore could go unnoticed" in text
    # The Checklist answer appears once (Observation), not twice (Observation + Impact).
    assert text.count("records a single restore test on 18 March 2025") == 1, text.count(
        "records a single restore test on 18 March 2025")


# -- Control points -----------------------------------------------------------------
# A Control-mode sheet with no question column stores "<control> -- <the control's
# expected evidence>" as id, name and question; the cell showed the evidence line.

_CONTROL_MODE_LABEL = "8.13 Information Backup — Backup logs, restore test reports, or equivalent verification."


@pytest.mark.parametrize("finding, label", [
    ({"control_id": _CONTROL_MODE_LABEL, "control_name": _CONTROL_MODE_LABEL,
      "requirement_question": _CONTROL_MODE_LABEL}, "8.13 Information Backup"),
    ({"control_id": _CONTROL_MODE_LABEL, "control_name": _CONTROL_MODE_LABEL}, "8.13 Information Backup"),
    # unchanged: a real auditor question, a Checklist question, a Selective control
    ({"control_id": "5.17", "requirement_question":
      "5.17 Authentication Information - Is password retry configured as 3?"},
     "Is password retry configured as 3?"),
    ({"control_id": "Q2", "requirement_question": "Whether NTP is enabled and synchronized?"},
     "Whether NTP is enabled and synchronized?"),
    ({"control_id": "8.17 Clock Synchronization", "control_name": "8.17 Clock Synchronization",
      "requirement_question": "8.17 Clock Synchronization"}, "8.17 Clock Synchronization"),
])
def test_control_points_cell(finding, label):
    assert rx._control_point_label(finding) == label


def test_vapt_and_pqc_reports_do_not_use_it():
    for fn in (rx._export_vapt_pdf, rx._export_vapt_docx, rx._export_pqc_pdf, rx._export_pqc_docx):
        assert "_iso_observation_and_impact" not in inspect.getsource(fn), fn.__name__
