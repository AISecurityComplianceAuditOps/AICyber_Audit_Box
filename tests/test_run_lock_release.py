# -*- coding: utf-8 -*-
"""Every way a run ends, or the workspace is reset, releases the run lock.

The page showed "Evidence locked / Scope locked while the scan runs" beside an
idle Run Audit Scan button, the morning after a scan: the poller's catch-all
branch (a run gone idle -- stopped, or lost with a server restart) put the Run
button back and left upload and scope locked, and so did creating a new
session or switching sessions while one ran.

Checked in a browser on a throwaway server: a scan running, the server killed
and restarted -> the old page kept everything locked beside the Run button;
this one releases it. A new session made during a run -> the old page locked
it; this one does not. Node is not on every machine, so this pins the source.
"""
import io
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, "src", "api", "static", "app.js")


def _src():
    return io.open(APP_JS, encoding="utf-8").read()


def _function(src, name):
    start = src.index(f"function {name}(")
    depth, i = 0, src.index("{", start)
    while True:
        depth += src[i] == "{"
        depth -= src[i] == "}"
        i += 1
        if depth == 0:
            return src[start:i]


def _branch(body, opener, closer):
    start = body.index(opener)
    return body[start:body.index(closer, start + len(opener))]


def test_every_end_of_a_run_in_the_poller_releases_the_lock():
    body = _function(_src(), "pollAuditProgress")
    for opener, closer in (
            ('} else if (data.status === "completed") {', '} else if (data.status === "idle"'),
            ('} else if (data.status === "idle" && data.checkpoint', '} else if (data.status === "failed")'),
            ('} else if (data.status === "failed") {', "} else {"),
            ("// If scan is idle, stopped, or not running", "} catch (err) {")):
        assert "_setRunLockedInputs(false)" in _branch(body, opener, closer), opener


def test_a_new_session_and_a_switch_release_an_old_runs_lock():
    src = _src()
    new = _function(src, "startNewAuditSession")
    reset = new[new.index("// ── Reset UI: Scan run button"):new.index("// ── Reset UI: Controls checkboxes")]
    assert "_setRunLockedInputs(false)" in reset
    switch = _function(src, "switchRecentSession")
    reset = switch[switch.index("// ── Reset UI: Scan run button"):switch.index("// ── Restore or Reset UI")]
    assert "_setRunLockedInputs(false)" in reset
    # and the running session is locked again after the switch
    assert "checkActiveSessionStatusOnSwitch();" in switch[switch.index("// ── Restore or Reset UI"):]


def test_discarding_a_checkpoint_releases_the_lock():
    body = _function(_src(), "discardCheckpointAndReset")
    assert "_setRunLockedInputs(false)" in body
