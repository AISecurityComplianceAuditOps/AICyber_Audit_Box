# -*- coding: utf-8 -*-
"""A framework the browser restored is gated like one the auditor picked.

    pytest tests/test_framework_gating_restore.py -v

WHY THIS EXISTS

A new VAPT session sometimes opened with the ISO scope buttons:

    TARGET FRAMEWORK          VAPT -- Vulnerability Assessment ... (15 controls)
    SCOPE DETECTION METHOD    [ Checklist | Control | Selective ]   <- none active
    Active: AI Auto-Scoping -- ...
    ANALYSIS MODE             [ Scanner | Quick Audit | (Deep Audit) ]

The scope buttons and the analysis modes follow the framework only when
onFrameworkChangeSuggestMode() runs: on the dropdown's change event, or from
applySessionFramework() when the framework CHANGES. Chrome and Firefox restore a
dropdown's value on reload, with no change event. The page then held VAPT while
the panel kept the page's starting state (ISO buttons, Deep), and the session
applied after login was VAPT too -- "already showing it", so nothing gated.

Reproduced in the real UI (Playwright, Edge): set the dropdown to VAPT without an
event, log in to a VAPT session -> ISO buttons and Deep. With the fix: AI
Auto-Scoping and Scanner. An ISO session's own choice of Quick survives
re-applying its framework, because the gating re-runs only when the buttons and
the framework disagree.
"""
import io
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, "src", "api", "static", "app.js")
INDEX = os.path.join(ROOT, "src", "api", "static", "index.html")


def _src(path):
    return io.open(path, encoding="utf-8").read()


def _fn(src, name):
    m = re.search(r"\n(?:async )?function " + re.escape(name) + r"\(.*?\n\}", src, re.S)
    assert m, "%s not found in app.js" % name
    return m.group(0)


def test_the_browser_is_told_not_to_restore_the_framework():
    tag = re.search(r'<select id="framework-select"[^>]*>', _src(INDEX), re.S)
    assert tag and 'autocomplete="off"' in tag.group(0)


def test_gating_reruns_only_when_the_panel_disagrees_with_the_framework():
    body = _fn(_src(APP_JS), "_ensureFrameworkGating")
    assert "_frameworkIsTechnical()" in body
    assert 'getElementById("btn-ai-scoping")' in body
    assert "onFrameworkChangeSuggestMode()" in body
    # Conditional, not unconditional: re-gating an ISO session resets Quick to Deep.
    assert re.search(r"if \(_frameworkIsTechnical\(\) !== aiShown\) onFrameworkChangeSuggestMode\(\)", body)


def test_applying_the_framework_already_shown_still_checks_the_gating():
    body = _fn(_src(APP_JS), "applySessionFramework")
    same = body[body.index("if (sel.value === match.value)"):]
    assert same.index("_ensureFrameworkGating()") < same.index("return false")


def test_the_page_checks_the_gating_on_load():
    src = _src(APP_JS)
    start = src.index('document.addEventListener("DOMContentLoaded"')
    block = src[start:start + 1500]
    assert block.index("loadFrameworkControls();") < block.index("_ensureFrameworkGating();")
