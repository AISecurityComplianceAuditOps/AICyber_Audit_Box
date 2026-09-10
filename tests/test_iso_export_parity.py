# -*- coding: utf-8 -*-
"""The three ISO report layouts must say the same thing about the same finding.

There are three of them -- the master-template DOCX, the programmatic DOCX used
when that template is missing, and the PDF -- and each is written out longhand.
They drift: the template DOCX read `impact`/`risk_impact` for its Impact column
while both export endpoints have only ever sent `business_impact`, so every DOCX
printed "Business Risk" boilerplate where the PDF printed the real narrative.
The report looked stale in Word and current in PDF, from one identical payload.
"""
import io
import os
import re

import pytest

import src.core.report_exporter as rx


FINDING = {
    "control_id": "8.17",
    "control_name": "8.17 Whether NTP is enabled and synchronized?",
    "control": "8.17 Clock Synchronization",
    "requirement_question": "Whether NTP is enabled and synchronized?",
    "status": "NON_COMPLIANT", "final_result": "NON_COMPLIANT", "severity": "P2 High",
    "gap_description": "The system clock is not synchronized with any time source.",
    "description": "The system clock is not synchronized with any time source.",
    # The distinctive string the Impact column must carry through to the document.
    "business_impact": "Log timestamps cannot be correlated across systems during an investigation.",
    "recommendation": "Configure chronyd against the approved internal NTP servers.",
    "source_files": "121_NTP_Server_Clock_Sync.jpg",
    "evidence_snippet": "System clock synchronized: no",
    "policy_status": "NOT_FOUND", "policy_assessment": "NON_COMPLIANT",
    "evidence_status": "FOUND", "evidence_assessment": "NON_COMPLIANT",
}

META = {"brand_firm": "Dhiware Technologies Pvt Ltd", "framework": "ISO 27001"}

_IMPACT_TEXT = "Log timestamps cannot be correlated"


def _obs_row_sources():
    """The three observation-row builders, as source text.

    Two of the three cannot be invoked directly in a test -- the fallback only
    runs when the master template is absent, and the PDF's row loop is buried in
    a 600-line function -- so the guard against them drifting apart again is read
    off the source itself. Crude, but it is the difference between catching this
    at commit time and catching it in a customer's Word document.
    """
    src = io.open(rx.__file__, encoding="utf-8").read()
    bounds = [
        ("template_docx", "def _export_iso_template_docx", "def export_docx_report"),
        ("fallback_docx", "def export_docx_report", "def export_pdf_report"),
        ("pdf", "def export_pdf_report", None),
    ]
    out = {}
    for name, start, end in bounds:
        i = src.index(start)
        j = src.index(end) if end else len(src)
        out[name] = src[i:j]
    return out


def test_every_iso_layout_reads_business_impact():
    for name, body in _obs_row_sources().items():
        assert "business_impact" in body, (
            "%s never reads business_impact -- its Impact column will print "
            "boilerplate while the other layouts print the real narrative" % name)


def test_every_iso_layout_uses_the_same_control_point_label():
    for name, body in _obs_row_sources().items():
        assert "_control_point_label(" in body, (
            "%s builds its Control points cell by hand -- on a question-based "
            "audit two rows under one control become indistinguishable" % name)


def test_the_docx_layouts_label_the_column_recommendation():
    """The PDF and the master template both say Recommendation.

    Asserted against the header list itself, not against any mention of the word
    in the file -- the first version of this test failed on the code comment
    explaining the rename.
    """
    fallback = _obs_row_sources()["fallback_docx"]
    header = re.search(r"hdr_obs_titles\s*=\s*\[(.*?)\]", fallback, re.S)
    assert header, "could not find the fallback observation header list"
    titles = [t.strip().strip("\"'") for t in header.group(1).split(",")]
    assert "Recommendation" in titles, titles
    assert "Suggestion" not in titles, titles

    # The master template ships the column labelled "Suggestion" and the exporter
    # renames it at build time; that rename is what keeps the two DOCX layouts
    # agreeing with the PDF, so it has to stay.
    template = _obs_row_sources()["template_docx"]
    assert '_set_cell_text(_cell, "Recommendation")' in template


@pytest.mark.skipif(
    not any(os.path.exists(p) for p in (
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(rx.__file__))),
                     "..", "VAPT", "Sample report.docx"),
        "VAPT/Sample report.docx")),
    reason="master template VAPT/Sample report.docx not present (it is gitignored by *.docx)")
def test_template_docx_prints_the_real_impact_not_boilerplate():
    """End to end through the actual template, when the template is on disk."""
    data = rx._export_iso_template_docx(
        "ISO 27001 Audit", [dict(FINDING)], [], "Reviewed", metadata=META)
    assert data, "template exporter returned None despite the template existing"

    from docx import Document
    doc = Document(io.BytesIO(data))
    obs_table = max(doc.tables, key=lambda t: len(t.columns))
    all_text = "\n".join(c.text for row in obs_table.rows for c in row.cells)

    assert _IMPACT_TEXT in all_text, "the real business impact never reached the Impact column"
    # The boilerplate must not be standing in for it.
    impact_cells = [row.cells[5].text.strip() for row in obs_table.rows[1:]
                    if len(row.cells) > 5 and row.cells[3].text.strip()]
    assert impact_cells, "no populated observation row found"
    assert not any(c == "Business Risk" for c in impact_cells), impact_cells


def test_observations_precedence_matches_across_layouts():
    """A finding whose text lives only in `description` must not export empty."""
    for name, body in _obs_row_sources().items():
        chain = re.search(r'gap_description.{0,220}?finding', body, re.S)
        assert chain, "%s: could not find the observation fallback chain" % name
        assert 'description' in chain.group(0), (
            "%s omits description from the observation chain" % name)
