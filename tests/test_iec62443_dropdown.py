# -*- coding: utf-8 -*-
"""IEC 62443 is in the Target Framework dropdown, and cannot run until its
controls exist.

    pytest tests/test_iec62443_dropdown.py -v

Asked for as a dropdown entry, ahead of the 121-control catalog. A bare entry
was not safe: the control list's filter returned every framework's controls
for a value it did not name, and /audit/start ignores a framework it does not
know, so a run would have carried the session's previous framework. Until
controls with standard "IEC62443" are in controls_data, the page shows that
they are not added yet and both the page and the server refuse the run. The
other eight frameworks are pinned unchanged.
"""
import os
import re

import pytest

from src.api.endpoints import audit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "src", "api", "static", "index.html"), encoding="utf-8").read()
JS = open(os.path.join(ROOT, "src", "api", "static", "app.js"), encoding="utf-8").read()

LABEL = "IEC 62443 – Industrial Communication Networks: Network and System Security (121 controls)"


def _framework_select():
    start = HTML.index('<select id="framework-select"')
    return HTML[start:HTML.index("</select>", start)]


def _options(select_html):
    return [(v, " ".join(re.sub(r"<[^>]+>", "", t).split()))
            for v, t in re.findall(r'<option value="([^"]+)">(.*?)</option>', select_html, re.S)]


def test_the_dropdown_offers_it_with_the_requested_wording():
    assert ("IEC62443", LABEL) in _options(_framework_select())


def test_the_other_frameworks_are_unchanged():
    values = [v for v, _ in _options(_framework_select())]
    assert values == ["ISO 27001", "NIST CSF 2.0", "IEC62443", "DPDP", "SOC2", "BCMS",
                      "XBOM", "VAPT", "PQC"]


def test_the_new_session_dialog_offers_it_too():
    """Both dropdowns are labelled Target Framework."""
    start = HTML.index('<select id="new-session-framework"')
    modal = HTML[start:HTML.index("</select>", start)]
    assert ("IEC62443", LABEL) in _options(modal)


def test_a_session_created_as_iec62443_moves_the_sidebar_to_it():
    family = JS[JS.index("function _frameworkFamily"):JS.index("function applySessionFramework")]
    assert 'return "IEC62443";' in family
    assert family.index('return "IEC62443";') < family.index('return "ISO";')


def test_the_control_list_shows_only_its_own_controls():
    assert 'if (selectedStd === "IEC62443") return isIec;' in JS
    assert "&& !isPqc && !isIec;" in JS, "an IEC control must never be counted as ISO"
    assert "iec62443-not-ready" in JS


def test_the_page_refuses_the_run_before_the_checklist_guard():
    guard = JS.index('_fwNow.value === "IEC62443"')
    assert guard < JS.index("// Customize needs questions, not controls")


@pytest.mark.parametrize("fw", ["ISO 27001", "NIST CSF 2.0", "DPDP", "SOC2", "BCMS", "XBOM",
                                "VAPT", "PQC", "", None])
def test_every_other_framework_starts_as_before(fw):
    assert audit._framework_not_ready(fw) is None


@pytest.mark.parametrize("fw", ["IEC62443", "IEC 62443", "iec-62443"])
def test_the_server_refuses_it_while_it_has_no_controls(fw):
    assert "not been added" in audit._framework_not_ready(fw)


def test_the_refusal_lifts_on_its_own_once_controls_are_added(monkeypatch):
    from src.core import controls_data
    monkeypatch.setattr(controls_data, "USE_CASES",
                        controls_data.USE_CASES + [{"standard": "IEC62443", "sl": 9999}])
    assert audit._framework_not_ready("IEC62443") is None


def test_the_server_refuses_before_any_state_is_touched():
    src = open(os.path.join(ROOT, "src", "api", "endpoints", "audit.py"), encoding="utf-8").read()
    body = src[src.index("def api_start_audit"):]
    assert body.index("_framework_not_ready(req.current_framework)") < body.index("_bg_running.add(bg_key)")
