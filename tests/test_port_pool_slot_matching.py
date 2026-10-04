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


def _fresh_pool(monkeypatch, env=None, slots=None, fail=False, status=200, body=None):
    """A pool built under the given environment, with /slots stubbed.

    `status`/`body` reproduce what a real llama-server sends while it is still
    loading its weights: HTTP 503 and an error OBJECT, not a list.
    """
    for k in ("MAX_LLM_CONNECTIONS", "LLM_HOSTS"):
        monkeypatch.delenv(k, raising=False)
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)

    import src.core.port_pool as pp
    importlib.reload(pp)
    pool = pp.LLMPortPoolManager()

    class _Resp:
        status_code = status

        @staticmethod
        def json():
            if body is not None:
                return body
            return [{"id": i, "is_processing": False} for i in range(slots or 0)]

    class _Requests:
        calls = 0

        @classmethod
        def get(cls, *_a, **_k):
            cls.calls += 1
            if fail:
                raise OSError("connection refused")
            return _Resp()

    monkeypatch.setitem(__import__("sys").modules, "requests", _Requests)
    pool._stub = _Requests
    pool._LIMIT_RETRY_AFTER_SEC = 0.0        # no waiting in tests
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


def _settles_to(pool, n, within=5.0):
    """The permits reach n once the helper thread has retired the extras."""
    import time
    deadline = time.time() + within
    while time.time() < deadline:
        if _permits(pool) == n:
            return True
        time.sleep(0.05)
    return False


def test_a_smaller_server_lowers_the_limit_to_its_slots(monkeypatch):
    """It used to stay at 32: requests beyond the server's 4 slots waited in
    llama-server's own queue with their HTTP timeout running, and timed out
    before starting. They now wait in the app."""
    pool = _fresh_pool(monkeypatch, slots=4)
    pool._match_server_slot_count()
    assert pool._limit_per_port == 4
    assert _settles_to(pool, 4)


def test_lowering_never_strands_a_request_holding_a_permit(monkeypatch):
    """The extras are taken back by a helper thread, so a request that already
    holds a permit finishes and releases it first."""
    pool = _fresh_pool(monkeypatch, slots=4)
    lock = list(pool.port_locks.values())[0]
    held = [lock.acquire(blocking=False) for _ in range(30)]      # 30 of 32 in use
    assert all(held)
    pool._match_server_slot_count()
    for _ in held:
        lock.release()
    assert _settles_to(pool, 4)


def test_an_unreachable_server_leaves_the_limit_alone(monkeypatch):
    """Exactly the behaviour before this existed."""
    pool = _fresh_pool(monkeypatch, slots=49, fail=True)
    pool._match_server_slot_count()
    assert _permits(pool) == 32


def test_a_failed_probe_costs_one_timeout_per_request_at_most_once(monkeypatch):
    """A down server must not charge every request a 5s timeout.

    This once asserted a single attempt, full stop. That was wrong for the
    normal case: llama-server answers 503 for about a minute while it loads, so
    one attempt meant the count was never learned. The guarantee that matters is
    that the COST is bounded -- attempts are capped and spaced -- not that there
    is only one.
    """
    pool = _fresh_pool(monkeypatch, slots=49, fail=True)
    pool._LIMIT_RETRY_AFTER_SEC = 3600.0
    for _ in range(20):
        pool._match_server_slot_count()
    assert pool._limit_attempts == 1, "a single burst of requests probed repeatedly"


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


# ── the server is still loading ──────────────────────────────────────────────
#
# Measured against a real llama-server on this machine: for 69 seconds after
# launch, /slots answers
#
#     HTTP 503  {"error":{"message":"Loading model","type":"unavailable_error"}}
#
# An audit started in that window is exactly when the first probe happens.

def test_a_loading_server_is_retried_rather_than_given_up_on(monkeypatch):
    """One attempt would leave the count unknown for the life of the process."""
    pool = _fresh_pool(monkeypatch, status=503,
                       body={"error": {"message": "Loading model"}})
    pool._match_server_slot_count()
    assert pool._limit_checked is False, "gave up while the model was still loading"
    assert pool._server_slot_count is None


def test_the_count_is_learned_once_the_server_finishes_loading(monkeypatch):
    """The real sequence: 503, 503, 503, then 40 slots."""
    pool = _fresh_pool(monkeypatch, slots=40)
    state = {"ready": False}

    class _Resp:
        @property
        def status_code(self):
            return 200 if state["ready"] else 503

        @staticmethod
        def json():
            if not state["ready"]:
                return {"error": {"message": "Loading model"}}
            return [{"id": i} for i in range(40)]

    class _Requests:
        @staticmethod
        def get(*_a, **_k):
            return _Resp()

    monkeypatch.setitem(__import__("sys").modules, "requests", _Requests)

    for _ in range(3):
        pool._match_server_slot_count()
    assert _permits(pool) == 32, "raised the limit before the server could answer"

    state["ready"] = True
    pool._match_server_slot_count()
    assert _permits(pool) == 40, "never recovered after the server became ready"
    assert pool._limit_checked is True, "kept probing after a real answer"


def test_an_error_object_is_never_counted_as_slots(monkeypatch):
    """len() of a dict counts its KEYS.

    {"error": {...}} would read as one slot, which through the audit cap would
    hold the whole appliance at its floor.
    """
    pool = _fresh_pool(monkeypatch, status=200,
                       body={"error": {"message": "Loading model"}})
    pool._match_server_slot_count()
    assert pool._server_slot_count is None, "an error object was counted as slots"
    assert _permits(pool) == 32


def test_retrying_is_bounded_so_an_absent_server_is_not_probed_forever(monkeypatch):
    pool = _fresh_pool(monkeypatch, fail=True)
    for _ in range(pool._LIMIT_MAX_ATTEMPTS + 5):
        pool._match_server_slot_count()
    assert pool._limit_attempts <= pool._LIMIT_MAX_ATTEMPTS, "unbounded probing"
    assert pool._limit_checked is True, "never stopped trying"


def test_attempts_are_spaced_out(monkeypatch):
    """Otherwise every queued request pays its own 5s timeout."""
    pool = _fresh_pool(monkeypatch, fail=True)
    pool._LIMIT_RETRY_AFTER_SEC = 3600.0
    pool._match_server_slot_count()
    first = pool._limit_attempts
    for _ in range(5):
        pool._match_server_slot_count()
    assert pool._limit_attempts == first, "probed again inside the retry interval"


def test_an_empty_slot_list_is_not_treated_as_an_answer(monkeypatch):
    pool = _fresh_pool(monkeypatch, slots=0)
    pool._match_server_slot_count()
    assert pool._server_slot_count is None
    assert _permits(pool) == 32
