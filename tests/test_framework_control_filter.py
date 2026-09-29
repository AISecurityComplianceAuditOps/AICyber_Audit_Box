# -*- coding: utf-8 -*-
"""The control panel files every control under its own framework.

    pytest tests/test_framework_control_filter.py -v

The page guessed a control's framework from its text, with "SOC" meaning
SOC 2. "Associated" and "Social" both contain it: ISO 5.9 and 5.10 ("...Other
Associated Assets") and VAPT-8 ("Social Engineering...") were listed under
SOC 2, so the ISO list showed 91 of its 93 controls -- an auditor choosing
controls by hand could not pick those two -- and SOC 2 showed 36 of 33.
/controls/framework now sends each control's "standard", and the page files by
it; the text is read only for a control without one.
"""
import os
import re
from collections import Counter

import pytest

from src.api.endpoints import controls
from src.core.controls_data import USE_CASES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS = open(os.path.join(ROOT, "src", "api", "static", "app.js"), encoding="utf-8").read()


@pytest.fixture
def panel(monkeypatch):
    monkeypatch.setattr(controls, "_require_auth", lambda request: {"username": "t", "role": "auditor"})
    import src.core.bg_worker as worker
    monkeypatch.setattr(worker, "_load_custom_use_cases", lambda force=False: [])
    return controls.api_get_framework_controls(None)["controls"]


def test_every_control_is_sent_with_its_framework(panel):
    assert len(panel) == len(USE_CASES)
    assert all(c["standard"] for c in panel)


def test_the_counts_are_the_catalogs(panel):
    assert Counter(c["standard"] for c in panel) == {
        "ISO 27001": 93, "SOC2": 33, "XBOM": 23, "NIST CSF 2.0": 22,
        "VAPT": 15, "DPDP": 15, "PQC": 12, "BCMS": 4}


@pytest.mark.parametrize("use_case,standard", [
    ("5.9 Inventory of Information and Other Associated Assets", "ISO 27001"),
    ("5.10 Acceptable Use of Information and Other Associated Assets", "ISO 27001"),
    ("VAPT-8 Social Engineering and Phishing Simulation", "VAPT"),
])
def test_the_three_controls_the_text_misfiled(panel, use_case, standard):
    assert [c["standard"] for c in panel if c["use_case"] == use_case] == [standard]


def test_the_page_files_by_the_standard_not_the_letters():
    body = JS[JS.index("async function loadFrameworkControls"):JS.index("function updateSelectedScopeCount")]
    assert 'cat.includes("SOC") || useCase.includes("SOC")' not in body
    assert "_STD_FAMILY[String(c.standard" in body
    assert "/\\bSOC ?2\\b/.test(cat)" in body, "the text fallback must match SOC 2 as a word"
    for std in ("ISO27001", "SOC2", "NISTCSF2.0", "VAPT", "DPDP", "BCMS", "XBOM", "PQC"):
        assert re.search(r'"%s":\s*"' % re.escape(std), body), std


def test_the_word_match_keeps_what_it_should():
    word = re.compile(r"\bSOC ?2\b")
    assert word.search("SOC 2 TYPE II — CONTROL ENVIRONMENT")
    assert word.search("SOC2 FRAMEWORK CONTROLS")
    assert not word.search("OTHER ASSOCIATED ASSETS")
    assert not word.search("SOCIAL ENGINEERING AND PHISHING SIMULATION")
