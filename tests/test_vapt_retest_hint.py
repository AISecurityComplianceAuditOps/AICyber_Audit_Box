# -*- coding: utf-8 -*-
"""After a VAPT scan, the Scan Workspace says how a retest starts.

    pytest tests/test_vapt_retest_hint.py -v

The retest choice appeared only once a file no version had scanned was
uploaded. Until then the page said nothing: an auditor who uploaded the same
report again saw no option, pressed Run, and replaced v1 with a fresh full
scan. Now a scanned session with nothing new shows the last version's count,
how to start a retest, what Run does meanwhile, and an Upload retest file
button -- without changing what Run does.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS = open(os.path.join(ROOT, "src", "api", "static", "app.js"), encoding="utf-8").read()
HTML = open(os.path.join(ROOT, "src", "api", "static", "index.html"), encoding="utf-8").read()
FN = JS[JS.index("async function refreshVaptRetestChoice"):JS.index("function vaptRetestSelected")]


def test_a_scanned_session_with_nothing_new_shows_the_hint():
    assert "if (!info.vapt || !info.has_findings) return hide();" in FN
    hint = FN[FN.index("if (!newFiles.length) {"):]
    assert "To retest, upload the <b>new</b> scan report" in hint
    assert "replaces unsaved findings" in hint, "say what Run does without a new file"


def test_the_hint_does_not_turn_run_into_a_retest():
    hint = FN[FN.index("if (!newFiles.length) {"):FN.index("return;", FN.index("if (!newFiles.length) {"))]
    assert 'box.dataset.next = "";' in hint
    assert "vapt-run-kind" not in hint, "no retest radio before there is a file to retest"
    selected = JS[JS.index("function vaptRetestSelected"):JS.index("function syncRunButtonForRetest")]
    assert "!box.dataset.next" in selected


def test_the_upload_button_opens_the_evidence_picker():
    assert "getElementById('evidence-file-input-panel').click()" in FN
    assert re.search(r'id="evidence-file-input-panel"[^>]*onchange="handleEvidenceUpload\(event\)"', HTML)


def test_a_session_that_is_not_vapt_or_not_scanned_shows_nothing():
    assert FN.index("if (!info.vapt || !info.has_findings) return hide();") < FN.index("if (!newFiles.length) {")
