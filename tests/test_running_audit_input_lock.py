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
