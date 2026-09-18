# -*- coding: utf-8 -*-
"""
Evidence cannot be changed while its audit is running.

    pytest tests/test_running_audit_input_lock.py -v

WHY THIS EXISTS

/audit/start snapshots what the run needs: the evidence bytes and the control
list are passed BY VALUE into the worker thread (the parameter is named
`selected_sls_copy`). So a mid-run change cannot corrupt the run -- the audit
stays internally consistent whatever happens on screen.

The damage is subtler, and worse for an audit product: THE SCREEN AND THE REPORT
COME TO DISAGREE. An auditor deletes a file mid-scan, watches it disappear from
the list, and the finished report still cites it -- because the worker is
holding bytes read before the delete. They believe they removed it. Nothing on
either surface reveals the contradiction.

Uploading mid-scan is the same failure quietly reversed: the file lands, the
list shows it, and the report never mentions it.

app.js already greyed out the scope panel, but a disabled attribute is not a
boundary -- a direct API call walks past it. These tests exercise the API
directly for exactly that reason.
"""
import re

import pytest

from src.api.endpoints import audit as audit_ep
from src.core.bg_state import _bg_lock, _bg_running


@pytest.fixture
def running():
    """Register a session as running, and always clean up."""
    sid = "pytest_lock_session"
    with _bg_lock:
        _bg_running.add(sid)
    yield sid
    with _bg_lock:
        _bg_running.discard(sid)
        _bg_running.discard(f"bg_{sid}")


@pytest.fixture
def running_bg_key():
    """The other key shape. /audit/start registers the raw session_id, but
    /audit/stop discards both it and "bg_{session_id}" -- so both forms exist in
    this codebase and the guard has to recognise either."""
    sid = "pytest_lock_bgkey"
    with _bg_lock:
        _bg_running.add(f"bg_{sid}")
    yield sid
    with _bg_lock:
        _bg_running.discard(f"bg_{sid}")


def test_a_running_session_refuses_the_change(running):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        audit_ep._assert_session_not_running(running, "delete evidence")
    assert exc.value.status_code == 409


def test_the_bg_prefixed_key_is_recognised_too(running_bg_key):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        audit_ep._assert_session_not_running(running_bg_key)
    assert exc.value.status_code == 409


def test_the_message_says_what_to_do_about_it(running):
    """A refusal an auditor cannot act on is only marginally better than silent
    corruption -- it has to name the action and the way out."""
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        audit_ep._assert_session_not_running(running, "delete evidence")
    detail = str(exc.value.detail)
    assert "delete evidence" in detail
    assert "Stop the audit" in detail


def test_an_idle_session_is_untouched():
    audit_ep._assert_session_not_running("pytest_not_running_at_all")


def test_the_guard_releases_when_the_run_ends():
    sid = "pytest_lock_release"
    with _bg_lock:
        _bg_running.add(sid)
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        audit_ep._assert_session_not_running(sid)
    with _bg_lock:
        _bg_running.discard(sid)
    audit_ep._assert_session_not_running(sid)   # no longer raises


# ── every mutation path is actually wired to it ──────────────────────────────

@pytest.mark.parametrize("handler,action", [
    ("api_upload_evidence", "add evidence"),
    ("api_delete_evidence_file", "delete evidence"),
    ("api_delete_all_evidence_files", "delete all evidence"),
    ("api_undo_delete_evidence_file", "restore evidence"),
])
def test_every_evidence_mutation_path_calls_the_guard(handler, action):
    """Undo is included deliberately: restoring a file mid-run puts it back on
    the screen while the running audit still ignores it, which is the same
    screen-versus-report divergence as the delete that preceded it."""
    import inspect
    src = inspect.getsource(getattr(audit_ep, handler))
    assert "_assert_session_not_running" in src, f"{handler} is unguarded"
    assert action in src, f"{handler} does not name what it refused"


def test_read_only_evidence_routes_are_not_guarded():
    """Listing evidence during a scan is how an auditor watches progress. Only
    the paths that MUTATE are refused."""
    import inspect
    src = inspect.getsource(audit_ep.api_get_session_evidence)
    assert "_assert_session_not_running" not in src


def _set_run_locked_inputs_source():
    """The body of app.js's _setRunLockedInputs, as text."""
    import io
    import os

    app_js = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "src", "api", "static", "app.js")
    src = io.open(app_js, encoding="utf-8").read()
    start = src.index("function _setRunLockedInputs(")
    end = src.index("\nfunction ", start + 1)
    return src[start:end]


def test_the_lock_restores_the_cursor_it_replaced():
    """Unlocking must put the cursor back, not test the value it just wrote.

    The lock swaps cursor:pointer for cursor:not-allowed so a frozen control
    stops advertising itself as clickable. The restore was written as one
    branch serving both directions:

        if (el.style.cursor === "pointer" || id === "scoping-excel-dropzone")
            el.style.cursor = locked ? "not-allowed" : "pointer";

    which is a one-way door. Locking rewrites the value, so unlocking tested
    "not-allowed" against "pointer", failed, and left the no-entry cursor in
    place for the rest of the session -- on buttons that were enabled, had
    pointer-events untouched, and worked perfectly when clicked. A finished
    audit left the scope panel looking broken, and a reload cleared it, so it
    never reproduced for whoever went to look.

    Read off the source because the behaviour is three lines of DOM styling in
    a browser-only function: a Playwright run needs the whole stack up, and
    this needs to fail at commit time.
    """
    body = _set_run_locked_inputs_source()

    assert "cursorBeforeLock" in body, (
        "the pre-lock cursor is not stashed, so unlocking cannot know what to "
        "restore -- see this test's docstring")

    # The specific shape of the original defect: one conditional assignment
    # deciding the cursor for both directions at once.
    assert not re.search(r'style\.cursor\s*=\s*locked\s*\?', body), (
        "the cursor is still set from a `locked ? ... : ...` expression guarded "
        "by a test on its own current value -- locking overwrites that value, "
        "so the unlock branch is unreachable")


def test_the_lock_restores_the_scope_badge():
    """Releasing the lock must clear the "scan in progress" badge.

    lockScopeDisplayToCheckpoint writes "N / M selected (locked — scan in
    progress)" into the scope badge. The only other writer is
    updateSelectedScopeCount, which runs when the auditor changes the
    selection -- so nothing cleared the suffix when the run ended. A resumed run
    that finished left the panel announcing a scan in progress next to controls
    that were editable again, until an unrelated click happened to recount.

    Same failure shape as the cursor: applied on the way in, with no matching
    step on the way out. Checked here so the pair cannot drift apart again.
    """
    body = _set_run_locked_inputs_source()

    assert "updateSelectedScopeCount" in body, (
        "nothing recounts the scope badge when the lock is released, so the "
        '"(locked — scan in progress)" suffix survives the run that set it')
