# -*- coding: utf-8 -*-
"""A stray backslash must not throw away four findings' remediation text.

    pytest tests/test_remediation_json_repair.py -v

WHY THIS EXISTS

Found during a load test on a customer server. The message was:

    AI recommendations did not complete for 3 of 61 batch(es); those findings
    show the standard parser-generated text.

That appeared with ONE user on an idle machine, where nothing can queue, so it
was not capacity. The application log gave the real reason, 25 times over:

    [REMEDIATION LLM] Batch of 4 finding(s) not enriched, keeping parser text:
    JSONDecodeError: Invalid \\escape: line 9 column 94 (char 781)

The enrichment prompt asks for JSON. JSON permits only a handful of backslash
escapes, and a model writing remediation text reaches for backslashes constantly
and legitimately: a Windows path to edit, a regex to validate with, an escape
sequence it is telling a developer to use. Any one of them made the whole reply
unparseable, and the batch fell back to generic wording -- four findings at a
time, silently, with the machine idle.

The repair runs only after a normal parse has already failed, so well-formed
output is never touched.

WHAT IT CANNOT FIX

"C:\\temp" is valid JSON -- \\t is a tab -- so it parses as C:<tab>emp and the
path is mangled. Guessing which backslashes the model "meant" would corrupt
genuine escapes, so that is left alone. Saving four findings' text with one
mangled path is better than losing all four, which is what happened before.
"""
import pytest

from src.core.parsers.remediation_llm import _extract_json_object


B = chr(92)


def _payload(remediation):
    return ('{"remediations":{"0":{"remediation":"%s","actionable":"steps"}}}'
            % remediation)


def _first(raw):
    return _extract_json_object(raw)["remediations"]["0"]["remediation"]


# ── what was being lost ──────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("Edit C:" + B + "Program Files" + B + "app.conf", "Edit C:" + B + "Program Files" + B + "app.conf"),
    ("Validate with " + B + "d+ only", "Validate with " + B + "d+ only"),
    ("Encode as " + B + "x3c script", "Encode as " + B + "x3c script"),
    ("Match ^" + B + "w+@" + B + "w+$", "Match ^" + B + "w+@" + B + "w+$"),
    ("Use " + B + "s for whitespace", "Use " + B + "s for whitespace"),
])
def test_an_invalid_escape_no_longer_loses_the_batch(text, expected):
    assert _first(_payload(text)) == expected


def test_the_exact_shape_from_the_customer_log():
    """Invalid escape deep in a multi-finding reply, as the log reported."""
    raw = ('{"remediations":{'
           '"0":{"remediation":"Apply output encoding.","actionable":"a"},'
           '"1":{"remediation":"Set HttpOnly.","actionable":"b"},'
           '"2":{"remediation":"Filter with ' + B + 'd{1,3} per octet.","actionable":"c"},'
           '"3":{"remediation":"Patch the service.","actionable":"d"}}}')
    out = _extract_json_object(raw)["remediations"]
    assert len(out) == 4, "the whole batch of four was still lost"
    assert out["2"]["remediation"] == "Filter with " + B + "d{1,3} per octet."


# ── what must not change ─────────────────────────────────────────────────────

def test_well_formed_output_is_untouched():
    raw = _payload("Apply context-aware output encoding.")
    assert _first(raw) == "Apply context-aware output encoding."


def test_real_json_escapes_still_mean_what_they_mean():
    """The repair must not double-escape a genuine newline or quote."""
    assert _first(_payload("line one" + B + "nline two")) == "line one\nline two"
    assert _first(_payload("say " + B + '"hello' + B + '"')) == 'say "hello"'
    assert _first(_payload("a" + B + "tb")) == "a\tb"


def test_a_unicode_escape_still_works():
    assert _first(_payload(B + "u0041pply")) == "Apply"


def test_a_malformed_unicode_escape_is_repaired_not_fatal():
    """\\u without four hex digits is invalid JSON; it used to lose the batch."""
    assert _first(_payload("path " + B + "users")) == "path " + B + "users"


def test_a_json_fence_is_still_stripped():
    raw = "```json\n" + _payload("Apply encoding.") + "\n```"
    assert _first(raw) == "Apply encoding."


def test_an_empty_or_junk_reply_still_raises():
    """A missing answer must still be reported, not silently accepted."""
    for bad in ("", "   ", "I cannot help with that."):
        with pytest.raises(ValueError):
            _extract_json_object(bad)


def test_truly_broken_json_still_raises():
    """The repair fixes escapes, not structure.

    JSONDecodeError subclasses ValueError, and a reply with no closing brace is
    rejected before parsing -- both are errors the caller already handles.
    """
    for broken in ('{"remediations": {"0": ', '{"remediations": {"0": }}'):
        with pytest.raises(ValueError):
            _extract_json_object(broken)


# ── the documented limit ─────────────────────────────────────────────────────

def test_a_path_whose_backslash_is_a_valid_escape_is_still_mangled():
    """C:\\temp is valid JSON -- \\t is a tab. Pinned so the limit is known.

    The batch survives, which is the point; the alternative was losing all four
    findings' text over one character.
    """
    assert _first(_payload("C:" + B + "temp")) == "C:\temp"


# ── a quote inside the text, and a reply cut off ──────────────────────────────
#
# Still seen at a customer after the backslash repair, in AI mode:
#     [REMEDIATION LLM] Batch of 4 finding(s) not enriched, keeping parser
#     text: JSONDecodeError: Expecting ',' delimiter: line 5 column 248
# The model quotes what to set -- 'Set the "Secure" flag' -- and one bare quote
# ends the JSON string. The reply is now read by its known shape instead.

def test_a_quote_inside_the_text_no_longer_loses_the_batch():
    raw = ('{"remediations":{'
           '"0":{"remediation":"Set the "Secure" and "HttpOnly" flags on the session cookie.",'
           '"actionable":"In web.xml set <secure>true</secure> and name it "JSESSIONID"."},'
           '"1":{"remediation":"Apply output encoding.","actionable":"Use the framework encoder."}}}')
    out = _extract_json_object(raw)["remediations"]
    assert out["0"]["remediation"] == 'Set the "Secure" and "HttpOnly" flags on the session cookie.'
    assert out["0"]["actionable"] == 'In web.xml set <secure>true</secure> and name it "JSESSIONID".'
    assert out["1"]["remediation"] == "Apply output encoding."


def test_a_raw_line_break_and_a_quote_together():
    raw = ('```json\n{"remediations": {"0": {"remediation": "Disable TLS 1.0.\nThen restart the "nginx" service.",'
           ' "actionable": "Set ssl_protocols TLSv1.2 TLSv1.3;"}}}\n```')
    out = _extract_json_object(raw)["remediations"]["0"]
    assert out["remediation"] == 'Disable TLS 1.0.\nThen restart the "nginx" service.'
    assert out["actionable"] == "Set ssl_protocols TLSv1.2 TLSv1.3;"


def test_a_reply_cut_off_keeps_the_entries_it_finished():
    """The unfinished entry is left out -- its finding is asked again alone."""
    raw = ('{"remediations": {"0": {"remediation": "Rotate the "admin" password.", "actionable": "Run passwd."},'
           ' "1": {"remediation": "Patch OpenSSH to 9.8", "actionable": "apt-get install --only-up')
    out = _extract_json_object(raw)["remediations"]
    assert out["0"]["remediation"] == 'Rotate the "admin" password.'
    assert "actionable" not in out.get("1", {})


def test_fields_in_the_other_order():
    raw = '{"remediations": {"0": {"actionable": "Set "HttpOnly".", "remediation": "Protect the "sid" cookie."}}}'
    out = _extract_json_object(raw)["remediations"]["0"]
    assert out == {"actionable": 'Set "HttpOnly".', "remediation": 'Protect the "sid" cookie.'}
