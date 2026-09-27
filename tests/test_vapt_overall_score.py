# -*- coding: utf-8 -*-
"""The OVERALL row of the VAPT summary table states what the findings state.

    pytest tests/test_vapt_overall_score.py -v

WHY THIS EXISTS

A PortSwigger (Burp) report assigns no CVSS score, so every row of the
exported summary table read "-" -- and the OVERALL row under them read "8.5
HIGH". The PDF invented it from the worst severity (8.5 for any HIGH, 10.0
CRITICAL, 5.5 MEDIUM, 2.5 otherwise). The Word report computed it another way,
the highest score, and printed "0.0 LOW" for the same 35 findings, 12 of them
HIGH. Now both print the worst severity among the OPEN findings and the highest
score a scanner reported for those findings ("-" when none did).
"""
import io
import re

import pytest
from docx import Document
from pypdf import PdfReader

from src.core.report_exporter import _vapt_overall, export_docx_report, export_pdf_report


def _f(title, severity, score=None, status="Non-Compliant"):
    return {"control_id": "VAPT-1", "title": title, "control": title, "severity": severity,
            "severity_score": score, "status": status,
            "final_result": "CLOSED" if status == "Closed" else None,
            "description": title + " was found.", "recommendation": "Fix it.",
            "evidence_snippet": "Target Host: https://portal.test/\nScanner:     Burp Suite"}


BURP = [_f("SQL injection", "HIGH"), _f("Cross-site scripting (reflected)", "HIGH"),
        _f("Cookie without HttpOnly flag set", "INFO")]
SCORED = [_f("Remote code execution", "CRITICAL", 9.8), _f("Weak cipher", "MEDIUM", 5.3),
          _f("Fixed long ago", "CRITICAL", 10.0, status="Closed")]


def test_no_reported_score_gives_no_overall_score():
    assert _vapt_overall(BURP) == (None, "HIGH")


def test_the_overall_score_is_the_highest_reported():
    open_ones = [f for f in SCORED if f["status"] != "Closed"]
    assert _vapt_overall(open_ones) == (9.8, "CRITICAL")


def test_a_lower_severity_findings_score_is_not_paired_with_the_worst_severity():
    """Qualys's MEDIUM Sweet32 at CVSS 7.5 beside a HIGH with no score: the row
    must not read "7.5 HIGH"."""
    assert _vapt_overall([_f("SQL injection", "HIGH"),
                          _f("Sweet32", "MEDIUM", 7.5)]) == (None, "HIGH")
    assert _vapt_overall([_f("A", "HIGH", 7.2), _f("B", "MEDIUM", 7.5)]) == (7.2, "HIGH")


def test_severity_words_as_the_modify_dialog_saves_them_are_read():
    assert _vapt_overall([_f("x", "High (CVSS 7.0-8.9)"), _f("y", "Low")]) == (None, "HIGH")


def test_nothing_open_gives_dashes():
    assert _vapt_overall([]) == (None, "-")


def _pdf_overall(findings):
    out = export_pdf_report("overall check", findings, [], "FINAL", audit_type="vapt")
    text = " ".join(" ".join((p.extract_text() or "") for p in PdfReader(io.BytesIO(out)).pages).split())
    m = re.search(r"OVERALL SCORE (\S+) (\S+)", text)
    return m.groups() if m else None


def _docx_overall(findings):
    out = export_docx_report("overall check", findings, [], "FINAL", audit_type="vapt")
    for t in Document(io.BytesIO(out)).tables:
        for row in t.rows:
            cells = [c.text.strip() for c in row.cells]
            if "OVERALL SCORE" in cells:
                i = cells.index("OVERALL SCORE")
                return cells[i + 1], cells[i + 2]
    return None


@pytest.mark.parametrize("findings, want", [
    (BURP, ("-", "HIGH")),          # was 8.5 HIGH in the PDF, 0.0 LOW in Word
    (SCORED, ("9.8", "CRITICAL")),  # the closed 10.0 does not count
])
def test_the_pdf_and_the_word_report_state_the_same_overall_row(findings, want):
    assert _pdf_overall([dict(f) for f in findings]) == want
    assert _docx_overall([dict(f) for f in findings]) == want
