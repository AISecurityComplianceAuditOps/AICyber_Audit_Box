# -*- coding: utf-8 -*-
"""
pii_redactor.py
Pure-regex PII sanitizer.

Two callers, wanting different things from an IP address:

  * DOCX/PDF export -- the report says which machine the evidence came from,
    so the address is masked to its last octet ("172.16.32.xxx (IP masked)").
    The auditor can still tell two hosts apart and trace a finding back to its
    screenshot; the exact machine does not leave the building.
  * The auditor-feedback / knowledge-loop path -- that text is replayed
    verbatim into a later audit's prompt, where the address is of no use to
    anyone, so it is removed outright with ip_style="redact".

VAPT and PQC exports pass redact_ip=False throughout: a vulnerable host's
address IS the report's content, not incidental PII.

Patterns handled:
  - Email addresses         → [EMAIL REDACTED]
  - IPv4 addresses          → 10.0.0.xxx (IP masked)   or   [IP REDACTED]
  - Phone numbers (IN/UK)   → [PHONE REDACTED]
"""

import re

# ── Compiled patterns (compiled once at import time) ──────────────────────────

_EMAIL_PATTERN = re.compile(
    r'[\w.+\-]+@[\w\-]+\.(?:[a-zA-Z]{2,})',
    re.IGNORECASE
)

_IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Covers +91-XXXXXXXXXX, 91-XXXXXXXXXX, 0XXXXXXXXXX, +44-XXXXXXXXXX formats.
# The country-code/trunk-zero marker below is REQUIRED, not optional -- an
# earlier version made it optional, which degraded the whole pattern into
# "any bare 10-14 digit run" and false-positived on ordinary long numbers in
# finding text (timestamps, ticket/asset IDs, version stamps), silently
# mangling them into "[PHONE REDACTED]" in exported reports.
_PHONE_PATTERN = re.compile(
    r'(?<!\d)'                        # not preceded by digit
    r'(?:'
        r'\+(?:91|44|1)[\s\-]'        # +91-XXXXXXXXXX / +91 XXXXXXXXXX / +44-... / +1-...
        r'|(?:91|44)-'                # 91-XXXXXXXXXX / 44-XXXXXXXXXX (dash required)
        r'|0(?=\d)'                    # 0XXXXXXXXXX (leading trunk zero)
    r')'
    r'\d[\d\s\-]{7,10}\d'            # the number body (allows internal spacing/dashes)
    r'(?!\d)',                         # not followed by digit
    re.IGNORECASE
)


_IP_MASK_MARKER = " (IP masked)"


def mask_ip_last_octet(text, marker=_IP_MASK_MARKER):
    """172.16.32.18 -> 172.16.32.xxx (IP masked).

    The marker is attached to the first masked address in the string only.
    Repeating it after every occurrence turned a finding that mentioned one
    host three times into a sentence that read as though three different
    things had been hidden.
    """
    if not text or not isinstance(text, str):
        return text
    state = {"marked": False}

    def _sub(match):
        octets = match.group(0).split(".")
        masked = ".".join(octets[:3]) + ".xxx"
        if state["marked"]:
            return masked
        state["marked"] = True
        return masked + marker

    return _IPV4_PATTERN.sub(_sub, text)

def redact_pii(text: str, redact_ip: bool = True, ip_style: str = "mask") -> str:
    """
    Replaces PII patterns in text with redaction tokens.
    Returns the sanitized string. Input is unchanged if no patterns match.

    Args:
        text: The raw string to sanitize.
        redact_ip: Whether to touch IPv4 addresses at all. Defaults to True
            (ISO compliance reports, where an IP is incidental PII).
            VAPT/pentest report exports pass False -- a vulnerable host's IP
            address IS the report's content, not PII to scrub; only
            email/phone are redacted there.
        ip_style: How to treat an IP when redact_ip is True.
            "mask" (default) keeps the subnet and hides the host:
            "172.16.32.xxx (IP masked)". This is what report exports want --
            the finding still says which machine it is about, which is the
            difference between a traceable audit and an anonymous one.
            "redact" removes it entirely: "[IP REDACTED]". Used by the
            auditor-feedback path, whose text is replayed into a later
            audit's prompt where no address is wanted at all.

    Returns:
        Sanitized string with PII replaced by redaction tokens.
    """
    if not text or not isinstance(text, str):
        return text

    # Order matters: email before phone (emails contain @ which won't match phone)
    text = _EMAIL_PATTERN.sub("[EMAIL REDACTED]", text)
    if redact_ip:
        if ip_style == "redact":
            text = _IPV4_PATTERN.sub("[IP REDACTED]", text)
        else:
            text = mask_ip_last_octet(text)
    text = _PHONE_PATTERN.sub("[PHONE REDACTED]", text)

    return text
