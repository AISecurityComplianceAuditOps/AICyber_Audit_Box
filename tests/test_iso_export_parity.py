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


def test_iso_pdf_renders_the_template_when_a_converter_exists(monkeypatch):
    """The ISO PDF must be the template DOCX rendered, not a second layout.

    This is the defect the whole path exists for: the DOCX was built from
    Sample report.docx while the PDF was written out longhand, so one payload
    produced two differently-branded documents and only the DOCX carried the
    firm's cover page and header.
    """
    called = {}

    def _fake_convert(docx_bytes, timeout=180):
        called["docx"] = docx_bytes
        return b"%PDF-1.7 rendered-from-template"

    monkeypatch.setattr(rx, "_docx_bytes_to_pdf", _fake_convert)
    monkeypatch.setattr(rx, "_export_iso_template_docx",
                        lambda *a, **k: b"PK\x03\x04 pretend-docx")

    out = rx.export_pdf_report(
        "ISO 27001 Audit", [dict(FINDING)], [], "Reviewed",
        audit_type="iso", metadata=META)

    assert called.get("docx") == b"PK\x03\x04 pretend-docx", (
        "the ISO PDF did not go through the template DOCX")
    assert out == b"%PDF-1.7 rendered-from-template"


def test_iso_pdf_falls_back_when_no_converter(monkeypatch):
    """A missing LibreOffice must degrade the look, never fail the export.

    At an air-gapped site nobody can install a converter, so a hard failure here
    would mean no report at all. The programmatic layout is worse-looking and
    still correct.
    """
    monkeypatch.setattr(rx, "_docx_bytes_to_pdf", lambda *a, **k: None)

    out = rx.export_pdf_report(
        "ISO 27001 Audit", [dict(FINDING)], [], "Reviewed",
        audit_type="iso", metadata=META)

    assert out, "export produced nothing when the converter was unavailable"
    assert bytes(out[:4]) == b"%PDF", "fallback did not produce a PDF"


def test_docx_to_pdf_returns_none_without_soffice(monkeypatch):
    """No converter on PATH is a None, not an exception.

    _docx_bytes_to_pdf imports shutil inside the function, which binds the same
    module object -- so patching shutil.which here reaches it.
    """
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert rx._docx_bytes_to_pdf(b"PK\x03\x04 not really a docx") is None


def _template_on_disk():
    """The template paths the exporter itself searches, in its own order.

    The skipif above checks only the VAPT copy; the exporter accepts the repo
    root copy too, so a test keyed to VAPT alone silently stops running on a
    machine that has only the other one.
    """
    base = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(rx.__file__)), "..", ".."))
    for candidate in (os.path.join(base, "VAPT", "Sample report.docx"),
                      os.path.join(base, "Sample report.docx")):
        if os.path.exists(candidate):
            return candidate
    return None


@pytest.mark.skipif(_template_on_disk() is None,
                    reason="master template not present (it is gitignored by *.docx)")
def test_template_docx_numbers_each_page_exactly_once():
    """The footer must carry one page number, not two.

    _add_page_number_field guards against double-numbering by looking for an
    existing PAGE field, and the guard was reading footer.paragraphs -- which in
    python-docx yields only the direct w:p children of w:ftr. This template
    keeps its page number inside nested content controls
    (w:ftr > w:sdt > w:sdtContent > w:sdt > w:sdtContent > w:p), so the guard
    saw a footer holding nothing but the classification line, concluded there
    was no page number, and added a second one. Every report exported from this
    template read "Page 1 of 9Page 1 of 9".

    It survived because nothing rendered the footer: the DOCX shows cached field
    text until Word recalculates, and the ISO PDF came from a different code
    path entirely. Counting the fields in the XML is what catches it at commit
    time instead of in a customer's report.
    """
    import zipfile

    data = rx._export_iso_template_docx(
        "ISO 27001 Audit", [dict(FINDING)], [], "Reviewed", metadata=META)
    assert data, "template exporter returned None despite the template existing"

    W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    import xml.etree.ElementTree as ET

    with zipfile.ZipFile(io.BytesIO(data)) as z:
        footers = [n for n in z.namelist() if re.match(r"word/footer\d*\.xml$", n)]
        assert footers, "no footer part in the exported document"
        for part in sorted(footers):
            root = ET.fromstring(z.read(part))
            # Both legal encodings: complex fields carry the instruction in
            # w:instrText, simple fields in a w:instr attribute.
            page = [t.text for t in root.iter(W + "instrText")
                    if t.text and re.search(r"\bPAGE\b", t.text)]
            page += [e.get(W + "instr") for e in root.iter(W + "fldSimple")
                     if re.search(r"\bPAGE\b", e.get(W + "instr") or "")]
            numpages = [t.text for t in root.iter(W + "instrText")
                        if t.text and "NUMPAGES" in t.text]
            numpages += [e.get(W + "instr") for e in root.iter(W + "fldSimple")
                         if "NUMPAGES" in (e.get(W + "instr") or "")]
            assert len(page) == 1, (
                "%s carries %d PAGE fields, expected 1 -- the page number is "
                "duplicated: %r" % (part, len(page), page))
            assert len(numpages) == 1, (
                "%s carries %d NUMPAGES fields, expected 1: %r"
                % (part, len(numpages), numpages))
