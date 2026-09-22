# -*- coding: utf-8 -*-
"""A finding the auditor threw out must not display a risk rating.

    pytest tests/test_nist_risk_panel.py -v

WHY THIS EXISTS

buildNistRiskPanelHtml() hides the NIST risk panel (likelihood, impact, risk
level) for a finding with nothing to rate. It checked for the literal
"FALSE_POSITIVE" -- but the finding card sends "Rejected", the Modify dialog
sends "Out Of Scope", and the reports spell it "False Positive" with a space.
None of those matched, so a false positive the auditor had rejected still
carried a rating such as "Risk: HIGH" on its card, beside a status saying it had
been thrown out.

It now uses _WORKFLOW_ONLY_STATUSES, the vocabulary the reports use to leave
those findings out -- itself kept in step with src/core/finding_status.py by
tests/test_finding_workflow_status.py.
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


def _panel(**finding):
    src = io.open(APP_JS, encoding="utf-8").read()
    fn = re.search(r"\nfunction buildNistRiskPanelHtml\(f\) \{.*?\n\}", src, re.S)
    const = re.search(r"\nconst _WORKFLOW_ONLY_STATUSES = \[[^\]]*\];", src)
    assert fn and const, "buildNistRiskPanelHtml or _WORKFLOW_ONLY_STATUSES not found"
    script = (const.group(0) + fn.group(0)
              + "\nglobal.escapeHtml = s => String(s);"
              + "\nconsole.log(JSON.stringify(buildNistRiskPanelHtml(%s)));"
              % json.dumps(finding))
    # utf-8 explicitly: the panel's HTML carries non-ASCII characters, and on a
    # Windows console text=True alone decodes node's output as cp1252 and fails.
    out = subprocess.run(["node", "-e", script], capture_output=True,
                         text=True, encoding="utf-8", timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


BASE = dict(likelihood="High", impact="High", risk_level="HIGH",
            final_result="NON_COMPLIANT", severity="P2 High")


@pytest.mark.parametrize("status", [
    "Rejected", "Out Of Scope", "Out of Scope", "False Positive",
    "FALSE_POSITIVE", "Dismissed", "Excluded",
])
def test_a_thrown_out_finding_shows_no_risk_rating(status):
    assert _panel(status=status, **BASE) == "", (
        "a finding marked %r still displays a NIST risk rating" % status)


@pytest.mark.parametrize("status", ["Non-Compliant", "Accepted", "Partially Compliant"])
def test_a_live_gap_still_shows_its_risk_rating(status):
    """Accept confirms the gap -- its rating must stay."""
    assert _panel(status=status, **BASE), (
        "the risk panel vanished from a live finding marked %r" % status)


def test_a_compliant_finding_still_hides_it_as_before():
    assert _panel(status="Compliant", **dict(BASE, final_result="COMPLIANT")) == ""
    assert _panel(status="Accepted", **dict(BASE, final_result="COMPLIANT")) == ""
