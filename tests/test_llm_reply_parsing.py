"""The XML reader has to survive what the model actually sends.

Gemma prefixes every reply with its own channel markers:

    <|channel>thought
    <channel|><status>NON_COMPLIANT</status>...

The parser looked for the first "<" and landed on "<|channel>". A "|" cannot
start an XML name, so ElementTree failed at column 7 on EVERY call, for as long
as this has been running, and the regex fallback quietly parsed the entire
audit. Nothing looked broken because the fallback recovers all 30 fields -- but
the primary parser had never once succeeded, and the fallback truncates a field
whose text contains a "<" when its closing tag is missing.

Captured from the live model, not invented.
"""
import xml.etree.ElementTree as ET

import pytest

from src.ai.audit_chains import _CHANNEL_MARKER_RE, _XML_TAG_START_RE

# Exactly what query_llm returned, first 240 chars.
REAL_REPLY = (
    "<|channel>thought\n<channel|><status>NON_COMPLIANT</status>\n"
    "<policy_present>Not Found</policy_present>\n"
    "<evidence_present>Found</evidence_present>\n"
    "<severity_score>3.0</severity_score>\n"
    "<evidence_strength>Strong</evidence_strength>"
)


def _clean(raw):
    body = _CHANNEL_MARKER_RE.sub("", raw)
    m = _XML_TAG_START_RE.search(body)
    return body[m.start():] if m else body


def test_the_real_reply_used_to_fail_and_now_parses():
    with pytest.raises(ET.ParseError):
        ET.fromstring("<root>%s</root>" % REAL_REPLY)      # what shipped
    root = ET.fromstring("<root>%s</root>" % _clean(REAL_REPLY))
    assert root.find("status").text == "NON_COMPLIANT"
    assert root.find("evidence_present").text == "Found"


def test_the_failure_was_at_column_7():
    """Pinning the symptom, because that is what the log shows."""
    with pytest.raises(ET.ParseError) as e:
        ET.fromstring("<root>%s</root>" % REAL_REPLY)
    assert "column 7" in str(e.value), str(e.value)


@pytest.mark.parametrize("marker", [
    "<|channel>thought<channel|>",
    "<|start|>",
    "<end|>",
])
def test_markers_in_either_order_are_stripped(marker):
    assert _clean(marker + "<status>COMPLIANT</status>") == "<status>COMPLIANT</status>"


def test_a_clean_reply_is_untouched():
    reply = "<status>COMPLIANT</status><severity>P4 Low</severity>"
    assert _clean(reply) == reply


def test_a_tag_name_must_start_with_a_letter_or_underscore():
    assert _XML_TAG_START_RE.search("<|channel>") is None
    assert _XML_TAG_START_RE.search("<status>") is not None
    assert _XML_TAG_START_RE.search("<_private>") is not None
