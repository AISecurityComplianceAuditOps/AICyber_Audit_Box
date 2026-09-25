"""Accept can be taken back, on every finding card.

Accept confirms the verdict the audit reached (see src/core/finding_status.py).
It was one-way: the card kept its Accept button, nothing on it said the finding
had been accepted, and there was no way back. An accepted card now says so and
offers "Undo Accept", which returns the finding to the status its verdict is
written as. The same rule restores a rejected finding: an informational
scanner finding goes back to "Informational", not to "Non-Compliant".

The page's own functions are run under Node where it is available.
"""
import io
import json
import os
import shutil
import subprocess

import pytest

APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "src", "api", "static", "app.js")


def _src():
    return io.open(APP_JS, encoding="utf-8").read()


def _function(src, name):
    start = src.index(f"function {name}(")
    depth, i = 0, src.index("{", start)
    while True:
        ch = src[i]
        depth += ch == "{"
        depth -= ch == "}"
        i += 1
        if depth == 0:
            return src[start:i]


def _run(expr):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    src = _src()
    script = "\n".join(_function(src, n) for n in ("statusBeforeReview", "acceptActionHtml"))
    script += "\nprocess.stdout.write(JSON.stringify(%s));\n" % expr
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.parametrize("finding,expected", [
    ({"final_result": "COMPLIANT", "severity": "N/A"}, "Compliant"),
    ({"final_result": "NON_COMPLIANT", "severity": "P2 High"}, "Non-Compliant"),
    ({"final_result": None, "severity": "INFO"}, "Informational"),
    ({"final_result": "NON_COMPLIANT", "severity": "INFO"}, "Informational"),
    ({"final_result": None, "severity": "HIGH"}, "Non-Compliant"),
])
def test_undo_returns_the_status_the_verdict_is_written_as(finding, expected):
    assert _run("statusBeforeReview(%s)" % json.dumps(finding)) == expected


def test_an_accepted_card_offers_undo_instead_of_accept():
    html = _run('acceptActionHtml({id: 7, status: "Accepted"})')
    assert "Undo Accept" in html and "undoAcceptFinding(7)" in html
    assert "'Accepted')" not in html


def test_an_unreviewed_card_offers_accept():
    html = _run('acceptActionHtml({id: 7, status: "Non-Compliant"})')
    assert "updateFindingWorkflowStatus(7, 'Accepted')" in html and "Undo" not in html


def test_both_card_layouts_use_it():
    """ISO and VAPT/PQC are rendered by two branches of renderFindingsList;
    neither may keep a hard-coded Accept button of its own."""
    src = _src()
    render = src[src.index("function renderFindingsList("):]
    render = render[:render.index("\nfunction ", 10)]
    assert render.count("acceptActionHtml(f)") == 2
    assert "onclick=\"updateFindingWorkflowStatus(${f.id}, 'Accepted')\"" not in render


def test_restore_after_reject_uses_the_same_rule():
    src = _src()
    restore = _function(src, "restoreFindingCard")
    assert "statusBeforeReview(" in restore


# ── remediation shown as points ──────────────────────────────────────────────

def _run_fmt(expr):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    src = _src()
    script = "\n".join(_function(src, n) for n in ("escapeHtml", "splitSentences", "remediationPoints",
                                                   "formatRemediationSteps"))
    script += "\nprocess.stdout.write(JSON.stringify(%s));\n" % expr
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_prose_remediation_is_one_point_per_sentence():
    text = ("Validate and whitelist allowed URLs/IP ranges. Block requests to internal/private IP "
            "ranges (10.x, 172.16-31.x, 192.168.x). Use a dedicated egress proxy.")
    assert _run_fmt("splitSentences(%s)" % json.dumps(text)) == [
        "Validate and whitelist allowed URLs/IP ranges.",
        "Block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x).",
        "Use a dedicated egress proxy."]
    html = _run_fmt("formatRemediationSteps(%s, '#123456')" % json.dumps(text))
    assert html.count("<li") == 3


def test_abbreviations_versions_and_single_sentences_are_not_split():
    assert _run_fmt('splitSentences("Use e.g. a proxy. Upgrade to 2.4.51 or later.")') == [
        "Use e.g. a proxy.", "Upgrade to 2.4.51 or later."]
    assert "<li" not in _run_fmt('formatRemediationSteps("Upgrade Apache to 2.4.51 or later.", "#123")')
    assert "<ol" in _run_fmt('formatRemediationSteps("1. Apply the patch. 2. Re-test the host.", "#123")')
