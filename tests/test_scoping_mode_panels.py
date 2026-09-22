# -*- coding: utf-8 -*-
"""Checklist mode must not show a control picker it does not use.

    pytest tests/test_scoping_mode_panels.py -v

WHY THIS EXISTS

Since 57af2e5, Checklist (internal name CUSTOMIZE) is pure document Q&A: the
questions are the audit items, no control is resolved for them, and none is
reported against. setScopingMode() therefore calls _setControlScopeVisible(false)
for that mode, and its own comment says why:

    The control list is hidden rather than merely ignored. It used to stay on
    screen with the matched controls ticked, which is a claim: it told the
    auditor this run was scoped to those controls and would report against them.

_setControlScopeVisible looks the block up by the id "target-controls-container-
box". That id appeared nowhere in index.html, so getElementById returned null,
the `if (box)` guard swallowed it, and the picker stayed on screen in exactly the
mode it was written to leave -- headed "Target Controls to Audit", with a
"0 / 108 selected" badge, above a run that resolves no controls at all.

Nothing raised and nothing looked broken, which is why a guard clause hiding a
missing element is worth a test of its own.

THE MODES THIS MUST NOT TOUCH

Control (EXCEL), Selective (MANUAL) and AI all call _setControlScopeVisible(true)
and are pinned below, because the block's natural display is block and showing it
was a no-op before this fix as well -- only Checklist changes behaviour.
"""
import io
import os
import re


STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "src", "api", "static")
APP_JS = os.path.join(STATIC, "app.js")
INDEX_HTML = os.path.join(STATIC, "index.html")


def _js():
    return io.open(APP_JS, encoding="utf-8").read()


def _html():
    return io.open(INDEX_HTML, encoding="utf-8").read()


def _mode_branch(name):
    """The body of setScopingMode's branch for one mode."""
    js = _js()
    body = js[js.index("function setScopingMode(mode)"):]
    body = body[:body.index("\nfunction ", 10)]
    marker = {
        "CUSTOMIZE": 'if (modeStr === "CUSTOMIZE"',
        "AI": 'if (modeStr === "AI"',
        "MANUAL": 'else if (modeStr === "MANUAL"',
        "EXCEL": "        // Default to EXCEL Upload Scope",
    }[name]
    start = body.index(marker)
    nxt = [body.find(m, start + 10) for m in
           ('if (modeStr === "AI"', 'else if (modeStr === "MANUAL"',
            "        // Default to EXCEL Upload Scope")]
    ends = [n for n in nxt if n > start]
    return body[start:min(ends)] if ends else body[start:]


# ── the element the guard looks for ──────────────────────────────────────────

def test_the_control_scope_block_exists_in_the_dom():
    html = _html()
    assert 'id="target-controls-container-box"' in html, (
        "_setControlScopeVisible() looks this block up by id and its `if (box)` "
        "guard silently does nothing when it is absent, so Checklist mode keeps "
        "showing a control picker for a run that resolves no controls")


def test_the_block_wraps_the_controls_list_and_nothing_else():
    """Hiding it must take the picker away, not part of another panel."""
    html = _html()
    start = html.index('id="target-controls-container-box"')
    start = html.rindex("<div", 0, start)
    depth, i = 0, start
    while i < len(html):
        if html.startswith("<div", i):
            depth += 1
            i += 4
            continue
        if html.startswith("</div>", i):
            depth -= 1
            i += 6
            if depth == 0:
                break
            continue
        i += 1
    block = html[start:i]
    ids = re.findall(r'id="([^"]+)"', block)
    for needed in ("controls-checkbox-container", "total-scope-badge",
                   "controls-search-input"):
        assert needed in ids, "%s is outside the block that gets hidden" % needed
    # The scoping mode buttons and the Excel dropzone must stay visible.
    for outside in ("btn-customize-scoping", "btn-excel-scoping",
                    "scoping-excel-dropzone", "framework-select"):
        assert outside not in ids, (
            "%s sits inside the block Checklist hides, so choosing Checklist "
            "would hide the control that chose it" % outside)


# ── the mode that changes ────────────────────────────────────────────────────

def test_checklist_hides_the_control_scope():
    assert "_setControlScopeVisible(false)" in _mode_branch("CUSTOMIZE")


def test_checklist_also_clears_any_selection_left_behind():
    """An invisible selection that still travels with the run is the bug this
    mode was rebuilt to remove."""
    branch = _mode_branch("CUSTOMIZE")
    assert "cb.checked = false" in branch, branch[-400:]


# ── the modes that must not ──────────────────────────────────────────────────

def test_control_mode_still_shows_the_control_scope():
    assert "_setControlScopeVisible(true)" in _mode_branch("EXCEL")


def test_selective_mode_still_shows_the_control_scope():
    assert "_setControlScopeVisible(true)" in _mode_branch("MANUAL")


def test_ai_mode_still_shows_the_control_scope():
    assert "_setControlScopeVisible(true)" in _mode_branch("AI")


def test_the_button_ids_still_mean_what_they_did():
    """btn-checklist-scoping is the SELECTIVE button -- the naming trap.

    Pinned so a later reading of the id as "the Checklist button" cannot quietly
    swap two modes over.
    """
    html = _html()
    for btn_id, mode in (("btn-customize-scoping", "CUSTOMIZE"),
                         ("btn-excel-scoping", "EXCEL"),
                         ("btn-checklist-scoping", "MANUAL"),
                         ("btn-ai-scoping", "AI")):
        seg = html[html.index('id="%s"' % btn_id):]
        seg = seg[:seg.index("</button>")]
        assert "setScopingMode('%s')" % mode in seg, (
            "%s no longer calls setScopingMode('%s')" % (btn_id, mode))
