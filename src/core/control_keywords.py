"""
Deterministic per-control keyword weights for retrieval scoring (src/core/retrieval.py).

Generated once at import time from each control's own id/label/expected-evidence text via
src/ai/keyword_generator.py::generate_keywords() (regex + synonym expansion, no LLM call) --
the same mechanism already used for custom controls, applied here to all USE_CASES entries
(the 93 standard ISO 27001 controls, plus the VAPT-* entries sharing that same list).

Weighting mirrors the fallback scheme retrieval.py already uses when no keywords are supplied
(control-id words at 2.0, label words at 1.0), then layers the curated/synonym-expanded terms
from generate_keywords() on top at 1.5 -- a pure superset, so this can only add retrieval
signal, never remove any that already existed.
"""
import re
from src.core.controls_data import USE_CASES
from src.ai.keyword_generator import generate_keywords


def _weighted_keywords(control_id: str, label: str, expected: str) -> dict:
    weights = {}
    for w in re.findall(r'\b[a-zA-Z0-9_\-]{3,}\b', (control_id or "").lower()):
        weights[w] = max(weights.get(w, 0), 2.0)
    for w in re.findall(r'\b[a-zA-Z0-9_\-]{3,}\b', (label or "").lower()):
        weights[w] = max(weights.get(w, 0), 1.0)
    for kw in generate_keywords(label or "", expected or ""):
        weights[kw] = max(weights.get(kw, 0), 1.5)
    return weights


# Keyed by uc["use_case"] -- the same identity string _build_controls_for_audit() uses as
# "control" for standard controls (src/core/bg_worker.py).
CONTROL_KEYWORDS = {
    uc["use_case"]: _weighted_keywords(uc["use_case"], uc.get("label", ""), uc.get("expected", ""))
    for uc in USE_CASES
}
