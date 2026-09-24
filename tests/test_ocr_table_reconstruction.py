# -*- coding: utf-8 -*-
"""A table photographed or scanned must come out of OCR as a table.

    pytest tests/test_ocr_table_reconstruction.py -v

WHY THIS EXISTS

A customer's VAPT report was uploaded and the audit produced no findings at
all. The report's findings table was a single image inside the PDF -- which is
how a scanned or pasted table arrives -- and OCR returned its 39 cell fragments
in the detector's own order, which the reader then joined with spaces:

    Sr. Vulnerabilities Severity CVE/CWE Recommendation Reference New/Repeat
    No. Enforce strict Vertical Privilege 1. High CWE-269 role-based access
    Link New Escalation control Properly Cryptographic 2. High CWE-310 ...

Every row and column destroyed. Four real HIGH findings -- privilege
escalation, cryptographic failure, broken authentication, IDOR -- unreadable by
any parser, and the title of each one split in half ("Vertical Privilege" in
one fragment, "Escalation" three fragments later).

The information needed to put it back was there the whole time. doctr reports
where every fragment sits; the reader was discarding the geometry and keeping
only the text. Fragments are now grouped into visual lines by vertical overlap,
lines into rows by the wider gaps that separate a table's rows from the leading
inside a wrapped cell, and each row's fragments into columns by their x
position -- which also rejoins the split title.

WHAT IT MUST NOT TOUCH

Prose, which has one column and one fragment per line, and the two-pane
screenshot layout that _line_columns already handles -- a Burp request beside
its response. Both are checked below, because this runs on every OCR'd image in
the product, including every ISO evidence screenshot.

The measurements in these tests are the real ones, read off the customer's
report: cell gaps of 0.025-0.042 and row separators of 0.074-0.088.
"""
import pytest

from src.core.parsers.doc_parsers import _grid_rows, _line_columns


# The customer's table, as doctr reported it: (x0, x1, y0, y1, text).
REAL_TABLE = [
    (0.016, 0.045, 0.040, 0.093, "Sr."),
    (0.077, 0.230, 0.077, 0.125, "Vulnerabilities"),
    (0.280, 0.986, 0.077, 0.137, "Severity CVE/CWE Recommendation Reference New/Repeat"),
    (0.016, 0.053, 0.111, 0.160, "No."),
    (0.517, 0.658, 0.199, 0.249, "Enforce strict"),
    (0.076, 0.253, 0.233, 0.293, "Vertical Privilege"),
    (0.016, 0.038, 0.263, 0.318, "1."),
    (0.279, 0.331, 0.263, 0.330, "High"),
    (0.390, 0.773, 0.261, 0.316, "CWE-269 role-based access Link"),
    (0.853, 0.901, 0.268, 0.314, "New"),
    (0.076, 0.179, 0.300, 0.348, "Escalation"),
    (0.515, 0.591, 0.332, 0.383, "control"),
    (0.517, 0.606, 0.408, 0.468, "Properly"),
    (0.077, 0.227, 0.442, 0.500, "Cryptographic"),
    (0.016, 0.037, 0.472, 0.530, "2."),
    (0.280, 0.330, 0.475, 0.535, "High"),
    (0.390, 0.655, 0.472, 0.532, "CWE-310 configure the"),
    (0.725, 0.773, 0.470, 0.525, "Link"),
    (0.854, 0.900, 0.477, 0.523, "New"),
    (0.078, 0.150, 0.512, 0.555, "Failure"),
    (0.515, 0.565, 0.539, 0.592, "hash"),
    (0.517, 0.606, 0.617, 0.677, "Properly"),
    (0.077, 0.152, 0.654, 0.698, "Broken"),
    (0.015, 0.037, 0.679, 0.737, "3."),
    (0.279, 0.330, 0.679, 0.746, "High"),
    (0.390, 0.629, 0.686, 0.737, "CWE-287 implement"),
    (0.725, 0.772, 0.679, 0.735, "Link"),
    (0.854, 0.901, 0.684, 0.730, "New"),
    (0.077, 0.231, 0.721, 0.762, "Authentication"),
    (0.517, 0.665, 0.755, 0.797, "authentication"),
    (0.517, 0.612, 0.829, 0.873, "sufficient"),
    (0.077, 0.237, 0.859, 0.909, "Insecure Direct"),
    (0.017, 0.034, 0.896, 0.935, "4."),
    (0.280, 0.330, 0.893, 0.953, "High"),
    (0.390, 0.636, 0.893, 0.953, "CWE-639 privilege to"),
    (0.725, 0.774, 0.891, 0.944, "Link"),
    (0.853, 0.901, 0.893, 0.939, "New"),
    (0.076, 0.255, 0.923, 0.985, "Object Reference"),
    (0.514, 0.634, 0.960, 1.000, "access data"),
]


# ── the customer's table ─────────────────────────────────────────────────────

def test_the_table_comes_back_as_rows():
    rows = _grid_rows(REAL_TABLE)
    assert rows is not None, "the table was not recognised as a grid"
    assert len(rows) == 5, rows          # one header row and four findings


def test_each_finding_lands_on_its_own_row_with_its_own_severity_and_cwe():
    rows = _grid_rows(REAL_TABLE)
    body = rows[1:]
    for n, (title, cwe) in enumerate([
            ("Vertical Privilege Escalation", "CWE-269"),
            ("Cryptographic Failure", "CWE-310"),
            ("Broken Authentication", "CWE-287"),
            ("Insecure Direct Object Reference", "CWE-639")]):
        assert title in body[n], (title, body[n])
        assert cwe in body[n], (cwe, body[n])
        assert "High" in body[n], body[n]


def test_a_cell_split_across_lines_is_rejoined():
    """"Vertical Privilege" and "Escalation" are one cell, three fragments apart."""
    rows = _grid_rows(REAL_TABLE)
    joined = "\n".join(rows)
    assert "Vertical Privilege Escalation" in joined
    assert "Insecure Direct Object Reference" in joined
    assert "Broken Authentication" in joined


def test_two_findings_never_share_a_row():
    rows = _grid_rows(REAL_TABLE)
    for row in rows[1:]:
        assert sum(row.count(c) for c in ("CWE-269", "CWE-310", "CWE-287", "CWE-639")) == 1, row


def test_the_rebuilt_table_actually_parses_into_findings():
    """The whole point: these rows must reach the report as findings."""
    from src.core.parsers import parse_tool_file
    text = "VAPT Penetration Testing Report\n" + "\n".join(_grid_rows(REAL_TABLE))
    actionable, info = parse_tool_file("VAPT_report.pdf", text, framework="vapt")
    found = actionable + (info if isinstance(info, list) else [])
    titles = sorted(f.title for f in found)
    assert titles == ["Broken Authentication", "Cryptographic Failure",
                      "Insecure Direct Object Reference",
                      "Vertical Privilege Escalation"], titles
    assert all(f.severity == "HIGH" for f in found)


# ── what it must leave alone ─────────────────────────────────────────────────

def test_ordinary_prose_is_not_treated_as_a_grid():
    """One fragment per line, one column: there is no table here."""
    prose = [(0.08, 0.90, 0.10 + i * 0.05, 0.14 + i * 0.05,
              "This is an ordinary sentence of running text number %d." % i)
             for i in range(8)]
    assert _grid_rows(prose) is None


def test_a_single_column_list_is_not_a_grid():
    hosts = [(0.08, 0.40, 0.10 + i * 0.05, 0.14 + i * 0.05, "https://host%d.example" % i)
             for i in range(6)]
    assert _grid_rows(hosts) is None


def test_too_few_fragments_are_left_alone():
    assert _grid_rows([(0.1, 0.2, 0.1, 0.2, "a"), (0.5, 0.6, 0.1, 0.2, "b")]) is None


def test_the_two_pane_screenshot_still_goes_to_the_column_reader():
    """A Burp request beside its response is _line_columns' case, not this one.

    Pinned because the grid runs on every OCR'd image in the product. If it
    started claiming side-by-side panes, a proof of concept would be spliced
    back together line by line -- the defect _line_columns exists to prevent.
    """
    # Two independent line flows, deliberately NOT aligned: that is what tells
    # panes apart from a table, whose cells do line up. _line_columns rejects
    # a perfectly paired layout on purpose, so a fixture built that way would
    # be testing the table rule instead.
    panes = []
    for i in range(7):
        y = 0.08 + i * 0.055
        panes.append((0.05, 0.40, y, y + 0.035, "left pane line %d" % i))
    for i in range(7):
        y = 0.11 + i * 0.062
        panes.append((0.55, 0.95, y, y + 0.035, "right pane line %d" % i))
    as_lines = [(x0, x1, y0, t) for x0, x1, y0, _y1, t in panes]
    columns = _line_columns(as_lines)
    assert columns is not None, "the two-pane layout is no longer detected as columns"
    assert len(columns) == 2, columns
    assert all("left pane" in l for l in columns[0]), columns[0]
    assert all("right pane" in l for l in columns[1]), columns[1]
