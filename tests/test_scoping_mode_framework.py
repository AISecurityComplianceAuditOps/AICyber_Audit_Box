# -*- coding: utf-8 -*-
"""The active scoping mode must always be one whose button is on screen.

    pytest tests/test_scoping_mode_framework.py -v

WHY THIS EXISTS

A VAPT session sometimes showed the scoping panel in two states at once:

    SCOPE DETECTION METHOD   [ AI Auto-Scoping ]      <- greyed, inactive
    Active: Control Scope -- Drag & drop or browse an Excel scoping matrix
    [ Upload Excel Scoping Matrix ]                   <- should be hidden
    No checklist to hand? Build one here or download a template

A technical framework (VAPT, PQC) takes its scope from the uploaded scan files,
so onFrameworkChangeSuggestMode() shows only AI Auto-Scoping and hides the three
checklist modes. That was enforced only at the moment the framework changed.
Three session paths then called setScopingMode('EXCEL') unconditionally --
switching to a session with no scoping cache, starting a new session, and
restoring a cached mode -- and none of them consulted the framework. EXCEL
brought the dropzone and the builder link back, rewrote the status line, and put
the active marker on the Excel button, which the framework had hidden. The one
visible button, AI Auto-Scoping, was left inactive and rendered grey.

It came and went because it depended on which of the two ran last.

The rule now lives in setScopingMode(), which every caller passes through, so no
call order can produce the mixed state. These tests run the real function under
node against a stand-in DOM, replaying the sequence that produced it.

THE MODES THIS MUST NOT TOUCH

On a governance framework (ISO, SOC 2, DPDP, BCMS, X-BOM) Control, Selective and
Checklist behave exactly as before -- pinned below, per the rule that a scope
change is made one mode at a time.
"""
import io
import json
import os
import re
import shutil
import subprocess

import pytest


APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "src", "api", "static", "app.js")

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node not installed")


def _fn(src, name):
    m = re.search(r"\nfunction " + re.escape(name) + r"\(.*?\n\}", src, re.S)
    assert m, "%s not found in app.js" % name
    return m.group(0)


# A DOM just large enough for setScopingMode: every element it touches by id,
# each carrying the style / classList / innerHTML it reads and writes.
_HARNESS = r"""
const ids = ["btn-ai-scoping", "btn-checklist-scoping", "btn-excel-scoping",
             "btn-customize-scoping", "scoping-excel-dropzone",
             "scoping-mode-status-note", "scoping-builder-entry",
             "target-controls-container-box", "btn-edit-scope",
             "scope-method-label", "framework-select"];
const els = {};
for (const id of ids) {
  const cls = new Set();
  els[id] = { id, value: "", innerHTML: "", innerText: "", style: { display: "" },
              classList: { add: c => cls.add(c), remove: c => cls.delete(c),
                           contains: c => cls.has(c) } };
}
global.document = {
  getElementById: id => els[id] || null,
  querySelectorAll: () => [],
};
global.window = {};
global.customEvidenceMappings = null;
global.updateSelectedScopeCount = () => {};
"""


def _run(framework, *modes):
    """Set the framework, apply each mode in turn, report the final panel."""
    src = io.open(APP_JS, encoding="utf-8").read()
    fns = "\n".join(_fn(src, n) for n in (
        "_frameworkIsTechnical", "_effectiveScopingMode",
        "_setControlScopeVisible", "_setBuilderEntryVisible", "setScopingMode"))
    script = _HARNESS + fns + """
els["framework-select"].value = %s;
for (const m of %s) setScopingMode(m);
const active = ["btn-ai-scoping","btn-checklist-scoping","btn-excel-scoping",
                "btn-customize-scoping"].filter(i => els[i].classList.contains("active-scope-mode"));
console.log(JSON.stringify({
  mode: window.currentScopingMode,
  active: active,
  dropzone: els["scoping-excel-dropzone"].style.display,
  status: els["scoping-mode-status-note"].innerHTML.replace(/<[^>]+>/g, ""),
}));
""" % (json.dumps(framework), json.dumps(list(modes)))
    out = subprocess.run(["node", "-e", script], capture_output=True,
                         text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


# ── the reported state ───────────────────────────────────────────────────────

def test_a_session_reset_on_vapt_stays_in_ai_mode():
    """The exact sequence: AI applied for VAPT, then a reset asks for EXCEL."""
    panel = _run("VAPT", "AI", "EXCEL")
    assert panel["mode"] == "AI", panel
    assert panel["active"] == ["btn-ai-scoping"], (
        "the active marker landed on a button the framework hides: %r" % panel)
    assert panel["dropzone"] == "none", (
        "the Excel dropzone came back on a VAPT session: %r" % panel)
    assert "Control Scope" not in panel["status"], panel


@pytest.mark.parametrize("mode", ["EXCEL", "Excel Scoping", "MANUAL", "CUSTOMIZE"])
def test_no_checklist_mode_can_be_applied_to_a_technical_framework(mode):
    for fw in ("VAPT", "PQC"):
        panel = _run(fw, mode)
        assert panel["mode"] == "AI", "%s on %s -> %r" % (mode, fw, panel)
        assert panel["active"] == ["btn-ai-scoping"], panel


def test_ai_on_a_technical_framework_is_unchanged():
    panel = _run("VAPT", "AI")
    assert panel["mode"] == "AI" and panel["active"] == ["btn-ai-scoping"]


# ── the other direction ──────────────────────────────────────────────────────

def test_ai_cannot_be_applied_to_a_governance_framework():
    """The AI button is hidden for ISO; a cached AI mode must not strand it."""
    panel = _run("ISO 27001", "AI")
    assert panel["mode"] == "EXCEL", panel
    assert panel["active"] == ["btn-excel-scoping"], panel


# ── the modes this must not touch ────────────────────────────────────────────

@pytest.mark.parametrize("fw", ["ISO 27001", "SOC2", "DPDP", "BCMS", "XBOM"])
def test_governance_modes_behave_exactly_as_before(fw):
    assert _run(fw, "EXCEL")["mode"] == "EXCEL"
    assert _run(fw, "MANUAL")["mode"] == "MANUAL"
    assert _run(fw, "CUSTOMIZE")["mode"] == "CUSTOMIZE"


def test_each_governance_mode_marks_its_own_button():
    """btn-checklist-scoping is the SELECTIVE button -- the naming trap."""
    assert _run("ISO 27001", "EXCEL")["active"] == ["btn-excel-scoping"]
    assert _run("ISO 27001", "MANUAL")["active"] == ["btn-checklist-scoping"]
    assert _run("ISO 27001", "CUSTOMIZE")["active"] == ["btn-customize-scoping"]


def test_the_rule_is_applied_inside_setScopingMode():
    """Not at each call site, where the next new caller would forget it."""
    src = io.open(APP_JS, encoding="utf-8").read()
    body = _fn(src, "setScopingMode")
    assert "_effectiveScopingMode(" in body, (
        "setScopingMode no longer routes the requested mode through the "
        "framework rule, so a caller passing EXCEL on VAPT breaks the panel again")
