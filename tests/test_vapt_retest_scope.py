# -*- coding: utf-8 -*-
"""A VAPT session keeps the scope the auditor set; findings do not narrow it.

After a scan, syncControlsScopeFromFindings (app.js) ticks only the controls the
findings belong to. For ISO that is what was evaluated. A VAPT finding exists
only where a vulnerability was found, so after the first scan of the
ginandjuice.shop demo 5 of 15 categories stayed ticked, and the retest -- run
on that narrowed scope -- dropped the new CORS and CSRF findings (or asked
"You have deselected 10 of 15 controls"). VAPT sessions now skip the sync;
every other framework is unchanged. Node is not required: app.js is checked.
"""
import os

import pytest

APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "src", "api", "static", "app.js")


@pytest.fixture(scope="module")
def sync():
    js = open(APP_JS, encoding="utf-8").read()
    start = js.index("function syncControlsScopeFromFindings(")
    return js[start:js.index("\n}\n", start)]


def _js_func(name):
    js = open(APP_JS, encoding="utf-8").read()
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}\n", start)]


def test_a_vapt_session_keeps_its_scope(sync):
    assert "if (isVaptOnlySession()) return;" in sync
    # before anything is ticked or unticked
    assert sync.index("if (isVaptOnlySession()) return;") < sync.index("cb.checked = isMatch;")


def test_the_run_lock_and_checklist_returns_still_come_first(sync):
    gate = sync.index("if (isVaptOnlySession()) return;")
    assert sync.index("if (window._scopeRunLocked) return;") < gate
    assert sync.index("if (window._sessionIsCustomizeRun) return;") < gate


def test_other_frameworks_still_sync_from_findings(sync):
    """ISO, NIST, SOC 2, DPDP, BCMS and PQC: the sync below the gate is unchanged."""
    body = sync[sync.index("if (isVaptOnlySession()) return;"):]
    for line in ("const evaluatedSls = new Set();", "cb.checked = isMatch;",
                 'console.warn("[Scope sync] findings did not match any control checkbox'):
        assert line in body
    assert sync.count("return;") == 5          # no checkboxes, run lock, checklist, VAPT, no findings


def test_only_a_vapt_session_counts():
    fn = _js_func("isVaptOnlySession")
    assert 'fw.includes("VAPT") && !fw.includes("PQC")' in fn
    assert "findingsSessionFramework" in fn


@pytest.mark.parametrize("framework, skipped", [
    ("VAPT Framework Controls", True), ("VAPT", True), ("ISO 27001", False), ("NIST CSF 2.0", False),
    ("SOC2", False), ("DPDP", False), ("BCMS", False), ("PQC", False), ("VAPT + PQC", False),
])
def test_which_sessions_skip_the_sync(framework, skipped):
    fw = framework.upper()
    assert (("VAPT" in fw) and ("PQC" not in fw)) is skipped
