# -*- coding: utf-8 -*-
"""The document-scope summary cannot hold an ISO audit at 0% for half an hour.

    pytest tests/test_context_summary_timeout.py -v

On a 16-core customer VM (2026-09-28) an ISO checklist audit sat at 0% for
over 30 minutes with nothing in the log. The model server had stalled on the
first request -- this optional summary, which runs before the first control --
and the call waited its full 1800s ("Read timed out. (read timeout=1800)")
although its own docstring promised a 15s hard timeout. It now gives up after
CONTEXT_SUMMARY_TIMEOUT_SEC (120s) and the audit goes on without the summary,
as it always did when the summary failed.
"""
import src.core.bg_worker as worker


def test_the_summary_waits_two_minutes_not_thirty(monkeypatch):
    seen = {}

    def _fake(prompt, model, **kw):
        seen["timeout"] = kw.get("timeout")
        return "A database access policy."

    monkeypatch.setattr("src.core.llm_client.query_llm", _fake)
    monkeypatch.delenv("CONTEXT_SUMMARY_TIMEOUT_SEC", raising=False)
    assert worker._generate_context_summary("--- FILE: a.docx ---\ntext", "gemma") == "A database access policy."
    assert seen["timeout"] == 120


def test_the_limit_can_be_raised_but_not_below_15s(monkeypatch):
    monkeypatch.setenv("CONTEXT_SUMMARY_TIMEOUT_SEC", "300")
    assert worker._context_summary_timeout() == 300
    monkeypatch.setenv("CONTEXT_SUMMARY_TIMEOUT_SEC", "1")
    assert worker._context_summary_timeout() == 15
    monkeypatch.setenv("CONTEXT_SUMMARY_TIMEOUT_SEC", "junk")
    assert worker._context_summary_timeout() == 120


def test_a_model_that_does_not_answer_is_skipped(monkeypatch):
    def _timeout(prompt, model, **kw):
        raise TimeoutError("Read timed out. (read timeout=120)")

    monkeypatch.setattr("src.core.llm_client.query_llm", _timeout)
    assert "unavailable" in worker._generate_context_summary("--- FILE: a.docx ---\ntext", "gemma")
