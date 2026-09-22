# -*- coding: utf-8 -*-
"""A finding the auditor threw out must not reach the customer.

    pytest tests/test_report_exclusions.py -v

WHY THIS EXISTS

The Reject button marks a false positive as "Rejected". The ISO report left it
out; the VAPT report printed it. Exported and checked:

    genuine finding in report  : True
    REJECTED finding in report : True

Eight exporters each carried their own list of statuses to leave out, and they
disagreed. _export_iso_template_docx excluded "Rejected" and "Dismissed". The
VAPT PDF, VAPT DOCX, PQC PDF and PQC DOCX excluded only "Out of Scope" and
"False Positive". The generic DOCX and the programmatic ISO PDF excluded only
"False Positive". And every list matched literally, so "Out of Scope" was caught
but "Out Of Scope" -- the spelling the Modify dialog actually sends -- was not.

For a VAPT engagement that meant rejecting a false positive changed nothing the
customer would ever see: the auditor had done the work of dismissing it, and it
was delivered as a finding regardless.

src/core/finding_status.py already owned the vocabulary, as
WORKFLOW_ONLY_STATUSES -- statuses that describe what happened to a finding
rather than to the control -- and every exporter now asks that one question.

THE CASE THIS MUST NOT CAUSE

"Accepted" confirms that a finding is correct. An accepted non-compliance is a
confirmed gap and must be in the report; it is pinned below.
"""
import io
import os
import re

import pytest

import src.core.report_exporter as rx
from src.core.report_exporter import _excluded_from_report


def _f(cid, name, status, final_result="NON_COMPLIANT"):
    return {"control_id": cid, "control_name": name, "severity": "P2 High",
            "status": status, "final_result": final_result,
            "asset_name": "web-01", "port": "443", "description": name,
            "recommendation": "fix it", "evidence_snippet": "e",
            "source_files": "scan.xml"}


def _pdf_text(data):
    try:
        from pypdf import PdfReader
    except ImportError:
        from PyPDF2 import PdfReader
    return " ".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages)


def _docx_text(data):
    from docx import Document
    doc = Document(io.BytesIO(data))
    parts = [p.text for p in doc.paragraphs]
    for t in doc.tables:
        for row in t.rows:
            parts.extend(c.text for c in row.cells)
    return " ".join(parts)


def _bytes(out):
    return out.getvalue() if hasattr(out, "getvalue") else out


# ── the rule ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("status", [
    "Rejected", "REJECTED", "rejected",
    "Dismissed", "False Positive", "FALSE_POSITIVE", "false-positive",
    "Out of Scope", "Out Of Scope", "OUT_OF_SCOPE", "Excluded",
])
def test_every_spelling_of_a_thrown_out_finding_is_excluded(status):
    assert _excluded_from_report({"status": status}), status


@pytest.mark.parametrize("status", [
    "Non-Compliant", "NON_COMPLIANT", "Compliant", "COMPLIANT",
    "Accepted", "Partially Compliant", "Open", "", None,
])
def test_a_live_finding_is_kept(status):
    assert not _excluded_from_report({"status": status}), status


def test_a_finding_with_no_status_at_all_is_kept():
    assert not _excluded_from_report({})
    assert not _excluded_from_report(None)


# ── the reported bug, in the reports themselves ──────────────────────────────

FINDINGS = [
    _f("VAPT-4", "GENUINE STORED XSS", "Non-Compliant"),
    _f("VAPT-5", "ACCEPTED CONFIRMED GAP", "Accepted"),
    _f("VAPT-9", "REJECTED FALSE POSITIVE", "Rejected"),
    _f("VAPT-8", "MODIFY SAID OUT OF SCOPE", "Out Of Scope"),
]


def test_the_vapt_pdf_leaves_out_what_the_auditor_rejected():
    text = _pdf_text(_bytes(rx._export_vapt_pdf(
        session_title="VAPT Audit Report", findings=[dict(f) for f in FINDINGS],
        resolved_list=[], status="Final", comments="", metadata={})))
    assert "GENUINE STORED XSS" in text
    assert "REJECTED FALSE POSITIVE" not in text, (
        "a false positive the auditor rejected is still in the customer's report")
    assert "MODIFY SAID OUT OF SCOPE" not in text, (
        '"Out Of Scope" -- the Modify dialog\'s spelling -- still reaches the report')


def test_an_accepted_finding_stays_in_the_vapt_pdf():
    """Accept confirms the gap. Excluding it would hide a real finding."""
    text = _pdf_text(_bytes(rx._export_vapt_pdf(
        session_title="VAPT Audit Report", findings=[dict(f) for f in FINDINGS],
        resolved_list=[], status="Final", comments="", metadata={})))
    assert "ACCEPTED CONFIRMED GAP" in text


def test_the_vapt_docx_leaves_out_what_the_auditor_rejected():
    text = _docx_text(_bytes(rx._export_vapt_docx(
        session_title="VAPT Audit Report", findings=[dict(f) for f in FINDINGS],
        resolved_list=[], status="Final", comments="", metadata={})))
    assert "GENUINE STORED XSS" in text
    assert "ACCEPTED CONFIRMED GAP" in text
    assert "REJECTED FALSE POSITIVE" not in text
    assert "MODIFY SAID OUT OF SCOPE" not in text


# ── one rule, not eight ──────────────────────────────────────────────────────

def test_no_exporter_keeps_its_own_list():
    """The drift came from each exporter writing the statuses out by hand."""
    src = io.open(rx.__file__, encoding="utf-8").read()
    for literal in ('not in ("Out of Scope"', '!= "False Positive"',
                    'not in ("Dismissed"'):
        assert literal not in src, (
            "an exporter is deciding exclusion from its own literal list again: "
            "%s" % literal)
    uses = len(re.findall(r"not _excluded_from_report\(f\)", src))
    assert uses >= 8, "expected every exporter to use the shared rule, found %d" % uses
