# -*- coding: utf-8 -*-
"""Coming back to a running scan locks upload and scope again, as starting it did.

checkActiveSessionStatusOnSwitch left the locking to lockScopeDisplayToCheckpoint,
which returns at once without a checkpoint -- and only an ISO run writes one. A
customer switched away from a running VAPT scan and back: upload, the remove
buttons and the scope panel were all editable while the scan ran. The evidence
list, redrawn on the switch, also brought back live remove buttons.

Checked in a browser on a throwaway server: the old page left 4 of 4 evidence
buttons live and the scope "Active"; this one locks them. Node is not on every
machine, so this pins the source.
"""
import io
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, "src", "api", "static", "app.js")


def _function(src, name):
    start = src.index(f"function {name}(")
    depth, i = 0, src.index("{", start)
    while True:
        depth += src[i] == "{"
        depth -= src[i] == "}"
        i += 1
        if depth == 0:
            return src[start:i]


def _src():
    return io.open(APP_JS, encoding="utf-8").read()


def test_a_running_session_is_locked_whether_or_not_it_has_a_checkpoint():
    body = _function(_src(), "checkActiveSessionStatusOnSwitch")
    running = body[body.index('if (data.status === "running")'):body.index("} else {")]
    lock = running.index("_setRunLockedInputs(true)")
    assert lock < running.index("lockScopeDisplayToCheckpoint(data.checkpoint)")
    # and the checkpoint path itself is unchanged: it still returns without one
    assert "if (!checkpoint) return;" in _function(_src(), "lockScopeDisplayToCheckpoint")


def test_an_idle_session_is_still_unlocked():
    body = _function(_src(), "checkActiveSessionStatusOnSwitch")
    assert "unlockScopeDisplay();" in body[body.index("} else {"):]


def test_a_redrawn_evidence_list_keeps_its_remove_buttons_locked_during_a_run():
    body = _function(_src(), "loadEvidenceFileList")
    tail = body[body.index("registry.appendChild(card);"):]
    assert "if (window._scopeRunLocked)" in tail
    assert '.modern-evidence-card button' in tail and "b.disabled = true" in tail
