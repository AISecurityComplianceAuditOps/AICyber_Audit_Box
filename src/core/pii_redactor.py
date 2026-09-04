# -*- coding: utf-8 -*-
"""
pii_redactor.py
Pure-regex PII sanitizer for audit report exports.
Applied only at DOCX/PDF export time — never touches DB records or Streamlit UI.

Patterns redacted:
  - Email addresses         → [EMAIL REDACTED]
  - IPv4 addresses          → [IP REDACTED]
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


def redact_pii(text: str, redact_ip: bool = True) -> str:
    """
    Replaces PII patterns in text with redaction tokens.
    Returns the sanitized string. Input is unchanged if no patterns match.

    Args:
        text: The raw string to sanitize.
        redact_ip: Whether to redact IPv4 addresses. Defaults to True (ISO
            compliance reports, where an IP is incidental PII). VAPT/pentest
            report exports pass False -- a vulnerable host's IP address IS
            the report's content, not PII to scrub; only email/phone are
            redacted there.

    Returns:
        Sanitized string with PII replaced by redaction tokens.
    """
    if not text or not isinstance(text, str):
        return text

    # Order matters: email before phone (emails contain @ which won't match phone)
    text = _EMAIL_PATTERN.sub("[EMAIL REDACTED]", text)
    if redact_ip:
        text = _IPV4_PATTERN.sub("[IP REDACTED]", text)
    text = _PHONE_PATTERN.sub("[PHONE REDACTED]", text)

    return text
