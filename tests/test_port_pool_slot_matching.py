# -*- coding: utf-8 -*-
"""The app must use as many AI slots as the server actually has.

    pytest tests/test_port_pool_slot_matching.py -v

WHY THIS EXISTS

Found during a load test on a customer server. Its LLM sized itself from the
hardware and said so:

    [LLM ENTRYPOINT] Detected 125.64GB and 64 core(s) ... -> 49 slot(s)

while the application capped itself at a hardcoded 32:

    [PORT POOL INITIALIZED] ... (32 max concurrent connections per port)

A third of the machine sat idle. Each user runs up to 4 enrichment requests at
once, so ten users ask for 40 -- which 49 slots would have absorbed with none
waiting, and 32 could not. The queue those users saw, and some of the batches
that timed out after 300s waiting, were caused by the cap rather than by the
hardware.

The number cannot be read at import: the pool is built while the LLM container
is still loading 12.7GB of weights, so /slots would not answer and every probe
would fall back to the same guess. It is read once on the first acquire, when
the server is certainly up.

Only ever upward. A Semaphore grows by releasing extra permits; lowering it
would strand requests already holding one. If the server reports fewer slots
than assumed, its own internal queue absorbs the excess -- which is what
happened before this existed.

An explicit MAX_LLM_CONNECTIONS is an operator's decision and is never
second-guessed.
"""
import importlib
import os

import pytest


def _fresh_pool(monkeypatch, env=None, slots=None, fail=False):
    """A pool built under the given environment, with /slots stubbed."""
    for k in ("MAX_LLM_CONNECTIONS", "LLM_HOSTS"):
        monkeypatch.delenv(k, raising=False)
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)

    import src.core.port_pool as pp
    importlib.reload(pp)
    pool = pp.LLMPortPoolManager()

    class _Resp:
        status_code = 200

        @staticmethod
        def json():
            return [{"id": i, "is_processing": False} for i in range(slots or 0)]

    class _Requests:
        @staticmethod
        def get(*_a, **_k):
            if fail:
                raise OSError("connection refused")
            return _Resp()

    monkeypatch.setitem(__import__("sys").modules, "requests", _Requests)
    return pool


def _permits(pool):
    """How many acquires the semaphore will allow without blocking."""
    lock = list(pool.port_locks.values())[0]
    taken = 0
    while lock.acquire(blocking=False):
        taken += 1
        if taken > 500:
            break
    for _ in range(taken):
        lock.release()
    return taken


# ── the customer's case ──────────────────────────────────────────────────────

def test_the_limit_rises_to_the_servers_slot_count(monkeypatch):
    pool = _fresh_pool(monkeypatch, slots=49)
    assert _permits(pool) == 32, "the starting guess changed"
    pool._match_server_slot_count()
    assert _permits(pool) == 49, (
        "the app is still capping itself below what the server offers")


def test_it_is_read_once_not_on_every_request(monkeypatch):
    pool = _fresh_pool(monkeypatch, slots=49)
    pool._match_server_slot_count()
    pool._match_server_slot_count()
    pool._match_server_slot_count()
    assert _permits(pool) == 49, "permits were released more than once"


# ── what must not change ─────────────────────────────────────────────────────

def test_an_explicit_setting_is_never_overridden(monkeypatch):
    """MAX_LLM_CONNECTIONS is an operator decision."""
    pool = _fresh_pool(monkeypatch, env={"MAX_LLM_CONNECTIONS": "8"}, slots=49)
    assert _permits(pool) == 8
    pool._match_server_slot_count()
    assert _permits(pool) == 8, "an explicit limit was overridden"


def test_a_smaller_server_never_lowers_the_limit(monkeypatch):
    """Lowering would strand requests already holding a permit."""
    pool = _fresh_pool(monkeypatch, slots=4)
    pool._match_server_slot_count()
    assert _permits(pool) == 32


def test_an_unreachable_server_leaves_the_limit_alone(monkeypatch):
    """Exactly the behaviour before this existed."""
    pool = _fresh_pool(monkeypatch, slots=49, fail=True)
    pool._match_server_slot_count()
    assert _permits(pool) == 32


def test_a_failed_probe_is_not_retried_forever(monkeypatch):
    """One attempt, so a down server costs one 5s timeout, not one per request."""
    pool = _fresh_pool(monkeypatch, slots=49, fail=True)
    pool._match_server_slot_count()
    assert pool._limit_checked is True


# ── it is wired into the path that uses it ───────────────────────────────────

def test_the_first_acquire_triggers_the_check():
    import io
    import os as _os
    src = io.open(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                "src", "core", "port_pool.py"), encoding="utf-8").read()
    body = src[src.index("def acquire_control_slot("):]
    body = body[:body.index("\n    def ", 10)] if "\n    def " in body[10:] else body
    assert "_match_server_slot_count()" in body, (
        "nothing calls the check, so the limit stays at the import-time guess")


def test_requests_is_imported_where_it_is_used():
    """This module imports requests locally; the probe must do the same.

    Written as a test because the first version relied on a module-level import
    that does not exist -- the NameError was caught by the probe's own except,
    so the feature silently did nothing while reporting success.
    """
    import io
    import os as _os
    src = io.open(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                "src", "core", "port_pool.py"), encoding="utf-8").read()
    fn = src[src.index("def _match_server_slot_count("):]
    fn = fn[:fn.index("\n    def ")] if "\n    def " in fn else fn
    assert "import requests" in fn, "the probe will raise NameError and silently no-op"
