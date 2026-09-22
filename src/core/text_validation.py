# -*- coding: utf-8 -*-
"""
Shared free-text input validation for API request models.

Any field here is user-supplied text that gets persisted to the DB and later
rendered back into the UI, exported into reports, or fed into an LLM prompt.
The frontend HTML-escapes on render (see escapeHtml() in app.js), but that is
a second layer, not the only one -- rejecting HTML/script-bearing input at the
API boundary is what's guaranteed to run regardless of which UI path (or a
direct API call) reaches the endpoint.
"""
import re
from typing import List, Optional

_FORBIDDEN_CHARS_RE = re.compile(r'[<>\x00-\x08\x0b\x0c\x0e-\x1f]')
# Control characters alone: NUL and the other C0 codes have no place in any text
# field, and Postgres rejects NUL outright. Tab, newline and carriage return are
# not in the range and stay allowed.
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')


def clean_safe_text(value: Optional[str], field_name: str, max_len: int, required: bool = False,
                    allow_markup: bool = False) -> str:
    """Strips, length-checks, and rejects HTML/control characters. Raises ValueError on failure.

    allow_markup: accept "<" and ">" while still rejecting control characters. For
    fields whose content is EVIDENCE, where markup is the substance rather than an
    attack: the proof of a stored XSS is "<script>...</script>", an HTTP response
    is HTML, and a correct XSS remediation names the tag it is about. Rejecting
    them meant a finding could not be edited at all once its evidence held markup
    -- the Modify dialog sends every field back, so even a status change failed.
    Default False, so every other caller keeps the old rule. Safe only because the
    UI escapes these fields on render; tests/test_finding_markup.py pins both.
    """
    value = (value or "").strip()
    if required and not value:
        raise ValueError(f"{field_name} is required.")
    if len(value) > max_len:
        raise ValueError(f"{field_name} must be {max_len} characters or fewer.")
    if allow_markup:
        if _CONTROL_CHARS_RE.search(value):
            raise ValueError(f"{field_name} may not contain control characters.")
    elif _FORBIDDEN_CHARS_RE.search(value):
        raise ValueError(f"{field_name} may not contain HTML tags or control characters.")
    return value


def clean_keywords(keywords: Optional[List[str]], max_count: int = 50, max_len: int = 60) -> List[str]:
    cleaned = []
    for kw in (keywords or [])[:max_count]:
        kw = clean_safe_text(kw, "Keyword", max_len)
        if kw:
            cleaned.append(kw)
    return cleaned
