# -*- coding: utf-8 -*-
"""Model calls wait while the model works, and the load fits the machine.

Measured on a 4-core VM: a VAPT batch was killed at the fixed 30-minute
request ceiling while the model was still writing (1 of 17 batches, one
auditor), and ISO controls cut off the same way were saved as NON_COMPLIANT.
The app also sent up to 32 requests to a model server with 3-4 slots, so the
rest waited in the server's queue with their timeout running.

  - query_llm streams; with no_time_limit it fails only on silence
    (LLM_STALL_TIMEOUT_SEC), never on duration.
  - port_pool sends the server no more requests than it has slots; the rest
    wait in the app, without a time limit when asked.
  - llm_capacity.fair_share sizes a scan's parallel work from the slots
    (cores and RAM) and the number of scans using the model.
  - VAPT batches run at that share and are retried at the end.
  - ISO: a model that stays unavailable through its retries gives a
    NOT_EVALUATED ("Not Assessed") control, never a NON_COMPLIANT finding.
"""
import json
import threading
import time
from unittest import mock

import pytest
import requests

import src.core.llm_client as lc
from src.core import llm_capacity


# -- streaming ----------------------------------------------------------------

class _Resp:
    def __init__(self, lines, status=200, raise_after=None):
        self.status_code, self._lines, self._raise = status, lines, raise_after
        self.text = "err"

    def iter_lines(self):
        for i, ln in enumerate(self._lines):
            if self._raise is not None and i == self._raise:
                raise requests.exceptions.ConnectionError("HTTPConnectionPool: Read timed out.")
            yield ln.encode() if isinstance(ln, str) else ln

    def close(self):
        pass


def _sse(**chunk):
    return "data: " + json.dumps(chunk)


def test_a_streamed_reply_reads_like_the_old_one():
    r = _Resp([_sse(content="", prompt_progress={"processed": 10, "total": 100}),
               "", _sse(content="Hello "), _sse(content="world"),
               _sse(content="", stop=True, stop_type="eos", tokens_evaluated=12, tokens_predicted=2)])
    out = lc._read_completion_stream(r)
    assert out == {"content": "Hello world", "stop_type": "eos", "tokens_evaluated": 12, "tokens_predicted": 2}


def test_silence_while_streaming_is_reported_as_the_model_unavailable():
    with pytest.raises(lc.LLMUnavailableError, match="timed out"):
        lc._read_completion_stream(_Resp([_sse(content="a"), _sse(content="b")], raise_after=1))


def _pool_stub():
    pool = mock.MagicMock()
    pool.acquire_control_slot.return_value.__enter__.return_value = "http://127.0.0.1:11434"
    return pool


def test_no_time_limit_means_a_stall_window_and_an_unlimited_slot_wait(monkeypatch):
    pool = _pool_stub()
    monkeypatch.setattr(lc, "port_pool_manager", pool)
    posted = {}

    def _post(url, json=None, stream=None, timeout=None):
        posted.update(stream=stream, timeout=timeout, payload=json)
        return _Resp([_sse(content="ok", stop=True, stop_type="eos")])

    monkeypatch.setattr(lc.requests, "post", _post)
    assert lc.query_llm("p", "gemma4:12b", no_time_limit=True) == "ok"
    assert posted["stream"] is True and posted["payload"]["stream"] is True
    assert posted["timeout"] == (10, lc.LLM_STALL_TIMEOUT_SEC)
    assert pool.acquire_control_slot.call_args.kwargs["wait_forever"] is True


def test_a_caller_budget_is_still_honoured(monkeypatch):
    """The context summary keeps its 120 s ceiling."""
    monkeypatch.setattr(lc, "port_pool_manager", _pool_stub())
    posted = {}

    def _post(url, json=None, stream=None, timeout=None):
        posted["timeout"] = timeout
        return _Resp([_sse(content="ok", stop=True, stop_type="eos")])

    monkeypatch.setattr(lc.requests, "post", _post)
    lc.query_llm("p", "m", timeout=120)
    assert posted["timeout"] == (10, 120)


@pytest.mark.parametrize("status, retryable", [(503, True), (500, True), (400, False)])
def test_server_errors(monkeypatch, status, retryable):
    monkeypatch.setattr(lc, "port_pool_manager", _pool_stub())
    monkeypatch.setattr(lc.requests, "post", lambda *a, **k: _Resp([], status=status))
    with pytest.raises(Exception) as e:
        lc.query_llm("p", "m", no_time_limit=True)
    assert isinstance(e.value, lc.LLMUnavailableError) == retryable


# -- the slot gate ------------------------------------------------------------

def _fresh_pool(monkeypatch, server_slots):
    from src.core.port_pool import LLMPortPoolManager
    monkeypatch.delenv("MAX_LLM_CONNECTIONS", raising=False)
    p = object.__new__(LLMPortPoolManager)
    p._initialize()
    fake = mock.MagicMock(status_code=200)
    fake.json.return_value = [{"id": i} for i in range(server_slots)]
    monkeypatch.setattr(requests, "get", lambda *a, **k: fake)
    return p


def test_the_app_sends_no_more_requests_than_the_server_has_slots(monkeypatch):
    p = _fresh_pool(monkeypatch, 3)
    p._match_server_slot_count()
    assert p._limit_per_port == 3
    lock = p.port_locks[p.ports[0]]
    deadline = time.time() + 5
    while time.time() < deadline:                 # the helper thread retires the extra permits
        got = 0
        while lock.acquire(blocking=False):
            got += 1
        for _ in range(got):
            lock.release()
        if got == 3:
            break
        time.sleep(0.05)
    assert got == 3


def test_waiting_for_a_slot_can_be_unlimited(monkeypatch):
    p = _fresh_pool(monkeypatch, 1)
    p._match_server_slot_count()
    time.sleep(0.3)
    order = []

    def _second():
        with p.acquire_control_slot(timeout=0.01, wait_forever=True):
            order.append("second")

    with p.acquire_control_slot():
        t = threading.Thread(target=_second)
        t.start()
        time.sleep(0.3)                           # well past timeout=0.01: still waiting, not failed
        order.append("first done")
    t.join(5)
    assert order == ["first done", "second"]


# -- fair share ---------------------------------------------------------------

@pytest.mark.parametrize("slots, cores, scans, share", [
    (3, 4, 1, 2),      # this VM: one spare on a small machine
    (4, 4, 2, 1),
    (16, 16, 1, 16),
    (16, 16, 3, 5),
    (16, 16, 20, 1),   # never below one
    (1, 2, 1, 1),
])
def test_fair_share(slots, cores, scans, share):
    assert llm_capacity.fair_share(slots=slots, cores=cores, scans=scans) == share


def test_a_scan_counts_once_while_it_uses_the_model():
    before = llm_capacity.active_scans()
    with llm_capacity.scan_using_llm("s1"):
        with llm_capacity.scan_using_llm("s1"):
            with llm_capacity.scan_using_llm("s2"):
                assert llm_capacity.active_scans() == before + 2
    assert llm_capacity.active_scans() == before


def test_the_slot_count_comes_from_llm_slots_first(monkeypatch):
    monkeypatch.setenv("LLM_SLOTS", "7")
    assert llm_capacity.model_slots() == 7


# -- VAPT batches run at the share ----------------------------------------------

def test_vapt_batches_never_exceed_the_fair_share(monkeypatch):
    import re
    from src.core.parsers import remediation_llm as rl
    monkeypatch.setattr(llm_capacity, "fair_share", lambda *a, **k: 2)
    live, peak, lock = [0], [0], threading.Lock()

    def _fake(prompt, model, **kw):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.15)
        with lock:
            live[0] -= 1
        n = len(re.findall(r"^\[\d+\]", prompt, re.MULTILINE))
        return json.dumps({"remediations": {str(i): "A specific remediation for this finding."
                                            for i in range(n)}})

    findings = [{"title": f"Finding {i}", "severity": "HIGH", "cve_list": [], "target": f"10.0.0.{i}",
                 "evidence": "e", "description": "", "remediation": "generic",
                 "remediation_actionable": "generic"} for i in range(10)]
    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake):
        rl.enrich_remediations(findings, model="x", pointwise=True)
    assert peak[0] == 2
    assert all(f["remediation"] != "generic" for f in findings)


def test_vapt_batches_have_no_time_limit():
    import inspect
    from src.core.parsers import remediation_llm as rl
    assert "no_time_limit=timeout is None" in inspect.getsource(rl._ask_batch)


# -- ISO: an unavailable model is never a NON_COMPLIANT finding -------------------

def _chain():
    from src.ai.audit_chains import get_generator_chain
    return get_generator_chain("gemma4:12b")


@pytest.mark.parametrize("err", [lc.LLMUnavailableError("LLM request timed out: silent"),
                                 requests.exceptions.ConnectionError("connection refused")])
def test_the_iso_chain_raises_instead_of_returning_a_finding(err):
    with mock.patch("src.core.llm_client.query_llm", side_effect=err), \
         mock.patch("src.core.llm_client.count_tokens", return_value=10):
        with pytest.raises(lc.LLMUnavailableError):
            _chain().invoke({"control_id": "8.17", "control_label": "Clock", "condensed_context": "x",
                             "summary_text": "", "expected_evidence": "", "feedback_section": "",
                             "standard": "ISO 27001", "timeout": None})


def _state(**kw):
    s = {"control_id": "8.17", "control_label": "8.17 Clock Synchronization", "llm_model": "gemma4:12b",
         "retrieved_context": "NTP synchronized: yes", "summary_text": "", "expected_evidence": "",
         "bg_key": None, "retry_count": 0, "audit_mode": "Deep", "draft_finding": None,
         "validation_error": None, "locked_filenames": [], "standard": "ISO 27001"}
    s.update(kw)
    return s


def test_an_iso_control_the_model_never_answers_is_not_assessed(monkeypatch):
    from src.ai import audit_graph as g
    calls = []

    class _Dead:
        last_token_stats = {}

        def invoke(self, args):
            calls.append(args.get("timeout", "absent"))
            raise lc.LLMUnavailableError("LLM request timed out: silent")

    monkeypatch.setattr(g, "get_generator_chain", lambda *a, **k: _Dead())
    monkeypatch.setattr("src.ai.knowledge_loop.get_auditor_feedback_few_shot", lambda *a, **k: "")
    out = g.generate_node(_state())
    assert len(calls) == 1 + g.LLM_RETRY_ATTEMPTS and set(calls) == {None}   # retried; no ceiling
    assert "timed out" in out["validation_error"]
    final = g.validate_node(_state(validation_error=out["validation_error"]))["final_finding"]
    assert final["status"] == "NOT_EVALUATED" and final["final_result"] == "NOT_EVALUATED"
    assert "NOT ASSESSED" in final["finding"]


def test_an_iso_control_that_recovers_on_retry_is_assessed(monkeypatch):
    from src.ai import audit_graph as g
    calls = []

    class _Flaky:
        last_token_stats = {}

        def invoke(self, args):
            calls.append(1)
            if len(calls) == 1:
                raise lc.LLMUnavailableError("LLM request timed out: silent")
            d = mock.MagicMock()
            d.model_dump.return_value = {"status": "COMPLIANT"}
            return d

    monkeypatch.setattr(g, "get_generator_chain", lambda *a, **k: _Flaky())
    monkeypatch.setattr("src.ai.knowledge_loop.get_auditor_feedback_few_shot", lambda *a, **k: "")
    out = g.generate_node(_state())
    assert len(calls) == 2 and out["draft_finding"] == {"status": "COMPLIANT"} and out["validation_error"] is None
