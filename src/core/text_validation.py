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


def clean_safe_text(value: Optional[str], field_name: str, max_len: int, required: bool = False) -> str:
    """Strips, length-checks, and rejects HTML/control characters. Raises ValueError on failure."""
    value = (value or "").strip()
    if required and not value:
        raise ValueError(f"{field_name} is required.")
    if len(value) > max_len:
        raise ValueError(f"{field_name} must be {max_len} characters or fewer.")
    if _FORBIDDEN_CHARS_RE.search(value):
        raise ValueError(f"{field_name} may not contain HTML tags or control characters.")
    return value


def clean_keywords(keywords: Optional[List[str]], max_count: int = 50, max_len: int = 60) -> List[str]:
    cleaned = []
    for kw in (keywords or [])[:max_count]:
        kw = clean_safe_text(kw, "Keyword", max_len)
        if kw:
            cleaned.append(kw)
    return cleaned
