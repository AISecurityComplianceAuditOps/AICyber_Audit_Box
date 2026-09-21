# -*- coding: utf-8 -*-
"""The ISO cover page, as it is actually delivered.

    pytest tests/test_iso_cover_layout.py -v

WHY THIS EXISTS

The cover comes from `Sample report.docx`, a real past audit by another firm, so
everything on it is that firm's design until it is deliberately changed. Three
things it carried were wrong for a Dhiware report and none of them raised:

  * every cover paragraph had a thinThickSmallGap border, which Word and
    LibreOffice both draw as a heavy decorative box around the page
  * the auditor logo was inserted with insert_paragraph_before(), which makes a
    BARE paragraph -- inside a bordered run that ended one box and started
    another, leaving the shield stranded in the gap between two boxes
  * the auditor block was padded with runs of empty paragraphs (four inside it,
    three more before the phone lines), so the contact details drifted down the
    page instead of reading as one block

The DOCX and the PDF agreed throughout, because the PDF is a LibreOffice render
of this very DOCX -- they were both wrong in the same way. None of it was
visible except by rendering the page and looking at it.
"""
import io

import pytest

from docx import Document

from src.core.report_exporter import _export_iso_template_docx


W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"

FINDING = {
    "control_id": "8.17", "control_name": "Clock Synchronization",
    "severity": "HIGH", "status": "Non-Compliant",
    "final_result": "NON_COMPLIANT", "description": "d",
    "recommendation": "r", "evidence_snippet": "e",
}


def _cover():
    buf = _export_iso_template_docx(
        session_title="ISO 27001 - Test - 22 Sept 2026",
        findings=[dict(FINDING)], resolved_list=[], status="Final", comments="",
        metadata={"brand_firm": "Dhiware Technologies Pvt Ltd"})
    data = buf.getvalue() if hasattr(buf, "getvalue") else buf
    if not data:
        pytest.skip("the ISO template did not render on this machine")
    doc = Document(io.BytesIO(data))
    end = next((i for i, p in enumerate(doc.paragraphs)
                if p.text.strip() == "Contents"), len(doc.paragraphs))
    return doc.paragraphs[:end]


def _border(p):
    pr = p._p.find(W + "pPr")
    return pr is not None and pr.find(W + "pBdr") is not None


def _picture(p):
    return bool(p._p.findall(".//" + A + "blip"))


def _index(cover, prefix):
    return next((i for i, p in enumerate(cover)
                 if p.text.strip().startswith(prefix)), None)


def test_the_cover_carries_no_decorative_border():
    """The template's box belongs to the firm the template came from."""
    boxed = [i for i, p in enumerate(_cover()) if _border(p)]
    assert not boxed, (
        "paragraph(s) %r still carry the template's page border, which renders "
        "as a heavy box around the cover" % (boxed,))


def test_the_auditor_logo_sits_above_a_bold_conducted_by():
    cover = _cover()
    logo = next((i for i, p in enumerate(cover) if _picture(p)
                 and i > len(cover) // 3), None)
    conducted = _index(cover, "Audit Conducted By")
    assert conducted is not None, "the cover has no 'Audit Conducted By:' line"
    assert logo is not None and logo < conducted, (
        "the auditor logo is missing from the foot of the cover, or sits below "
        "'Audit Conducted By:'")
    assert all(r.bold for r in cover[conducted].runs), (
        "'Audit Conducted By:' heads the block and should be bold like the "
        "other cover headings")


def test_the_auditor_block_has_no_runs_of_blank_lines():
    """Padding inside the block scattered the contact details down the page."""
    cover = _cover()
    start = _index(cover, "Audit Conducted By")
    assert start is not None

    run, offenders = 0, []
    for i in range(start, len(cover)):
        if cover[i].text.strip():
            run = 0
            continue
        run += 1
        if run > 1:
            offenders.append(i)
    assert not offenders, (
        "consecutive blank paragraphs at %r inside the auditor block -- the "
        "contact details will drift apart" % (offenders,))


def test_the_contact_details_are_all_present():
    """Tightening the block must not delete a line from it."""
    cover = _cover()
    for prefix in ("Audit Conducted By", "Dhiware Technologies",
                   "Ph:", "Mobile:", "Email"):
        assert _index(cover, prefix) is not None, "%r was lost from the cover" % prefix


def test_the_four_cover_fields_survive():
    cover = _cover()
    for prefix in ("Dates of Audit", "Date of Report", "Order reference",
                   "Document ID"):
        assert _index(cover, prefix) is not None, "%r is missing" % prefix
