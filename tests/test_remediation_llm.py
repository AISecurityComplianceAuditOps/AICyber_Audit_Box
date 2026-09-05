# -*- coding: utf-8 -*-
"""
Hybrid parser+LLM remediation enrichment -- VAPT/PQC "Scanner" mode, opt-in.

    pytest tests/test_remediation_llm.py -v

WHY THIS EXISTS

nmap_parser.py writes the literal sentence "Investigate service misconfiguration
and apply vendor patches/hardening." on every open-port finding it produces,
verbatim, three times in the file -- whether the port is a stale Telnet service
or a modern web server with one weak cipher. Reported directly: "i was getting
generic answers".

control_mapper.py::get_actionable_remediation() has the same problem one level
down: it fills "remediation_actionable" from a ~35-keyword template table, so
every finding matching a given keyword (e.g. every "telnet" finding) gets the
identical developer-facing template text.

enrich_remediations() rewrites ONLY "remediation" and "remediation_actionable",
grounded in that finding's own evidence, and ONLY when the auditor explicitly
opts in (ai_recommendations=True). Every other field -- severity, cve_list,
control_id, title, evidence -- is never touched, and any LLM failure leaves
the original parser-generated text exactly as it was. The two rewritten
fields also fail independently: a short/missing reply for one does not block
the other from being accepted on the same finding.

These tests cover everything that does not require a live model: batching,
JSON extraction tolerance, the fallback path, and the wiring that keeps this
feature off by default. Live-model verification (does the text actually
improve) is a separate manual check -- the model on THIS box is a 12B
reasoning-styled gguf auto-selected by commit 139f6e4's fallback list, and a
single grounded answer took 87.5s here, which is far too slow for a pytest run.
"""
from unittest import mock

import pytest

from src.core.parsers.remediation_llm import (_clip, _enrich_batch,
                                              _extract_json_object,
                                              _format_finding_block,
                                              enrich_remediations)

GENERIC = "Investigate service misconfiguration and apply vendor patches/hardening."
GENERIC_ACTIONABLE = "Disable the affected service or restrict access via firewall rules."


def _finding(**kw):
    base = {"title": "Nmap: Open Port", "severity": "MEDIUM", "cve_list": [],
            "target": "10.0.0.5", "evidence": "23/tcp open telnet",
            "description": "", "remediation": GENERIC,
            "remediation_actionable": GENERIC_ACTIONABLE}
    base.update(kw)
    return base


# ── JSON extraction tolerance ────────────────────────────────────────────────

def test_plain_json_object():
    assert _extract_json_object('{"remediations": {"0": "x"}}') == {"remediations": {"0": "x"}}


def test_fenced_json_is_unwrapped():
    raw = '```json\n{"remediations": {"0": "x"}}\n```'
    assert _extract_json_object(raw) == {"remediations": {"0": "x"}}


def test_fence_with_no_language_tag():
    raw = '```\n{"remediations": {"0": "x"}}\n```'
    assert _extract_json_object(raw) == {"remediations": {"0": "x"}}


def test_leading_reasoning_text_before_the_object_is_stripped():
    """The model this was tested against opens every reply with a
    `<|channel>thought` template header before its real content -- the
    extractor has to find the object regardless of what precedes it."""
    raw = '<|channel>thought\n<channel|>Here is my analysis.\n{"remediations": {"0": "x"}}'
    assert _extract_json_object(raw) == {"remediations": {"0": "x"}}


def test_empty_response_raises():
    with pytest.raises(ValueError):
        _extract_json_object("")
    with pytest.raises(ValueError):
        _extract_json_object("   ")


def test_no_object_at_all_raises():
    with pytest.raises(ValueError):
        _extract_json_object("<|channel>thought\n<channel|>")


def test_malformed_json_raises_rather_than_returning_garbage():
    """ValueError covers both failure points: no closing brace at all (caught
    by the brace-matching check before json.loads runs) and a brace present
    but invalid inside (caught by json.loads itself -- JSONDecodeError is a
    ValueError subclass). Either way, _enrich_batch's except Exception treats
    it as a failure and keeps the original text, which is the only thing that
    actually matters here."""
    with pytest.raises(ValueError):
        _extract_json_object('{"remediations": {"0": "unterminated')
    with pytest.raises(ValueError):
        _extract_json_object('{"remediations": {"0": "bad", }}')


# ── clipping ──────────────────────────────────────────────────────────────────

def test_clip_leaves_short_text_alone():
    assert _clip("short", 100) == "short"


def test_clip_truncates_and_marks_it():
    out = _clip("x" * 500, 50)
    assert len(out) <= 52
    assert out.endswith("…")


def test_clip_handles_none():
    assert _clip(None, 50) == ""


# ── finding formatting ───────────────────────────────────────────────────────

def test_format_includes_cves_when_present():
    block = _format_finding_block(0, _finding(cve_list=["CVE-2017-5638"]))
    assert "CVE-2017-5638" in block


def test_format_says_none_when_no_cves():
    block = _format_finding_block(0, _finding(cve_list=[]))
    assert "none" in block


def test_format_never_crashes_on_missing_keys():
    """A dict shape this loose has to survive a caller that forgot a key,
    since it is fed from bg_worker.py's own dict construction, not a
    guaranteed schema."""
    block = _format_finding_block(0, {})
    assert "[0]" in block


# ── the fallback contract: any failure keeps the original text ──────────────

def test_llm_exception_leaves_remediation_untouched():
    findings = [_finding()]
    with mock.patch("src.core.llm_client.query_llm", side_effect=RuntimeError("down")):
        enrich_remediations(findings, model="x", timeout=5)
    assert findings[0]["remediation"] == GENERIC


def test_malformed_llm_response_leaves_remediation_untouched():
    findings = [_finding()]
    with mock.patch("src.core.llm_client.query_llm", return_value="not json at all"):
        enrich_remediations(findings, model="x", timeout=5)
    assert findings[0]["remediation"] == GENERIC


def test_response_missing_the_remediations_key_is_a_failure():
    findings = [_finding()]
    with mock.patch("src.core.llm_client.query_llm", return_value='{"wrong_key": {}}'):
        enrich_remediations(findings, model="x", timeout=5)
    assert findings[0]["remediation"] == GENERIC


def test_a_too_short_reply_for_one_finding_does_not_poison_the_batch():
    """A blank or near-blank reply is a per-finding failure, not a whole-batch
    one -- the other findings in the same response may well be fine."""
    findings = [_finding(title="A"), _finding(title="B")]
    payload = '{"remediations": {"0": "ok", "1": "Patch the identified telnet service on port 23 and disable it if unused."}}'
    with mock.patch("src.core.llm_client.query_llm", return_value=payload):
        enrich_remediations(findings, model="x", timeout=5)
    assert findings[0]["remediation"] == GENERIC          # "ok" is under 15 chars, rejected
    assert findings[1]["remediation"] != GENERIC           # long enough, accepted


def test_a_successful_response_replaces_the_text():
    findings = [_finding()]
    payload = '{"remediations": {"0": "Disable the Telnet service on port 23 and replace it with SSH."}}'
    with mock.patch("src.core.llm_client.query_llm", return_value=payload):
        enrich_remediations(findings, model="x", timeout=5)
    assert findings[0]["remediation"] == "Disable the Telnet service on port 23 and replace it with SSH."


# ── deterministic fields are never written ───────────────────────────────────

def test_only_the_remediation_key_is_ever_written():
    f = _finding(severity="CRITICAL", cve_list=["CVE-1234-5678"], target="10.0.0.9",
                title="Original Title", evidence="original evidence", control_id="VAPT-3")
    before = dict(f)
    payload = '{"remediations": {"0": "Something completely different and specific."}}'
    with mock.patch("src.core.llm_client.query_llm", return_value=payload):
        enrich_remediations([f], model="x", timeout=5)
    for key in ("severity", "cve_list", "target", "title", "evidence", "control_id"):
        assert f[key] == before[key], f"'{key}' was modified"
    assert f["remediation"] != before["remediation"]


# ── remediation_actionable: same rewrite, independent fallback ──────────────

def test_a_dict_reply_updates_both_remediation_and_actionable():
    findings = [_finding()]
    payload = ('{"remediations": {"0": {'
               '"remediation": "Disable the Telnet service on port 23.", '
               '"actionable": "Run: systemctl disable telnetd; ufw deny 23/tcp."'
               '}}}')
    with mock.patch("src.core.llm_client.query_llm", return_value=payload):
        enrich_remediations(findings, model="x", timeout=5)
    assert findings[0]["remediation"] == "Disable the Telnet service on port 23."
    assert findings[0]["remediation_actionable"] == "Run: systemctl disable telnetd; ufw deny 23/tcp."


def test_a_short_actionable_is_rejected_independently_of_remediation():
    """The two fields fail independently -- a bad reply for one must not throw
    away a good reply for the other on the same finding."""
    findings = [_finding()]
    payload = ('{"remediations": {"0": {'
               '"remediation": "Disable the Telnet service on port 23 entirely.", '
               '"actionable": "ok"'
               '}}}')
    with mock.patch("src.core.llm_client.query_llm", return_value=payload):
        enrich_remediations(findings, model="x", timeout=5)
    assert findings[0]["remediation"] == "Disable the Telnet service on port 23 entirely."
    assert findings[0]["remediation_actionable"] == GENERIC_ACTIONABLE  # "ok" rejected, kept


def test_a_bare_string_reply_leaves_actionable_untouched():
    """Backward-compat path: a model that flattens the object to a plain string
    only ever updates "remediation" -- "remediation_actionable" is left as the
    parser's own template text, not blanked out."""
    findings = [_finding()]
    payload = '{"remediations": {"0": "Disable the Telnet service on port 23."}}'
    with mock.patch("src.core.llm_client.query_llm", return_value=payload):
        enrich_remediations(findings, model="x", timeout=5)
    assert findings[0]["remediation"] == "Disable the Telnet service on port 23."
    assert findings[0]["remediation_actionable"] == GENERIC_ACTIONABLE


def test_only_remediation_and_actionable_keys_are_ever_written():
    f = _finding(severity="CRITICAL", cve_list=["CVE-1234-5678"], target="10.0.0.9",
                title="Original Title", evidence="original evidence", control_id="VAPT-3")
    before = dict(f)
    payload = ('{"remediations": {"0": {'
               '"remediation": "Something completely different and specific.", '
               '"actionable": "Something completely different and developer-facing."'
               '}}}')
    with mock.patch("src.core.llm_client.query_llm", return_value=payload):
        enrich_remediations([f], model="x", timeout=5)
    for key in ("severity", "cve_list", "target", "title", "evidence", "control_id"):
        assert f[key] == before[key], f"'{key}' was modified"
    assert f["remediation"] != before["remediation"]
    assert f["remediation_actionable"] != before["remediation_actionable"]


# ── batching ──────────────────────────────────────────────────────────────────

def test_batches_do_not_exceed_the_configured_size():
    import src.core.parsers.remediation_llm as mod
    calls = []

    def _fake_query(prompt, model, **kw):
        # Count findings in the prompt by counting bracketed indices.
        import re
        calls.append(len(re.findall(r"^\[\d+\]", prompt, re.MULTILINE)))
        return '{"remediations": {}}'

    findings = [_finding(title=f"Finding {i}") for i in range(20)]
    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake_query):
        enrich_remediations(findings, model="x", timeout=5)
    assert all(c <= mod._BATCH_SIZE for c in calls)
    assert sum(calls) == 20


def test_empty_findings_list_is_a_no_op():
    assert enrich_remediations([], model="x") == []


def test_a_failed_batch_does_not_stop_later_batches():
    """20 findings, first batch's call raises, second batch's call succeeds --
    the second batch's findings must still be enriched."""
    import src.core.parsers.remediation_llm as mod
    calls = {"n": 0}

    def _fake_query(prompt, model, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("first batch fails")
        return '{"remediations": {"0": "Batch two succeeded with a specific remediation."}}'

    findings = [_finding(title=f"F{i}") for i in range(mod._BATCH_SIZE + 1)]
    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake_query):
        enrich_remediations(findings, model="x", timeout=5)
    assert findings[0]["remediation"] == GENERIC                    # batch 1 failed
    assert findings[mod._BATCH_SIZE]["remediation"] != GENERIC       # batch 2 succeeded


# ── the stop-token fix, pinned so it cannot regress silently ────────────────

def test_the_fence_stop_token_is_not_sent():
    """The reasoning-styled model this was verified against opens every reply
    with a template header and is EXPECTED to answer inside a ```json fence.
    query_llm's default stop list includes "```" (tuned for the ISO/VAPT
    XML-tag chains, where a fence never legitimately appears) -- sending it
    here matched the model's own opening fence and truncated every single
    response to nothing. Confirmed by direct A/B test: identical prompt, only
    the stop list changed, empty response became a complete grounded answer."""
    captured = {}

    def _fake_query(prompt, model, **kw):
        captured.update(kw)
        return '{"remediations": {"0": "A specific remediation."}}'

    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake_query):
        enrich_remediations([_finding()], model="x", timeout=5)
    assert "```" not in (captured.get("stop") or [])


def test_grammar_constrained_json_mode_is_not_used():
    """format="json" showed the identical empty-response failure as the fence
    stop token, on this model -- the prompt instruction plus tolerant
    extraction is what actually works, so this is not sent either."""
    captured = {}

    def _fake_query(prompt, model, **kw):
        captured.update(kw)
        return '{"remediations": {"0": "A specific remediation."}}'

    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake_query):
        enrich_remediations([_finding()], model="x", timeout=5)
    assert captured.get("format") is None


# ── opt-out wiring ───────────────────────────────────────────────────────────

def test_enabled_by_default_on_the_request():
    """Enrichment is ON by default.

    It was off, on the reasoning that "Scanner" mode should stay zero-AI unless
    asked. In practice the canned text it replaces is exactly what was reported as
    generic, and an auditor should not have to discover a checkbox to get a usable
    report. The pure-parser scan is still one untick away, and the findings are
    identical either way -- see test_only_the_remediation_key_is_ever_written.
    """
    from src.api.endpoints.audit import StartAuditRequest
    req = StartAuditRequest(session_id="s", selected_sls=[1], model_choice="llama.cpp")
    assert req.ai_recommendations is True


def test_can_still_be_turned_off_explicitly():
    """The zero-AI path must remain reachable -- it is what makes "no AI touched
    these findings" a statement an auditor can defend."""
    from src.api.endpoints.audit import StartAuditRequest
    req = StartAuditRequest(session_id="s", selected_sls=[1], model_choice="llama.cpp",
                            ai_recommendations=False)
    assert req.ai_recommendations is False


def test_the_worker_only_imports_the_module_when_asked():
    import inspect
    from src.core import bg_worker
    src = inspect.getsource(bg_worker._run_fast_technical_vapt_bg)
    guard_idx = src.index("if ai_recommendations and all_findings:")
    import_idx = src.index("from src.core.parsers.remediation_llm import enrich_remediations")
    assert guard_idx < import_idx, "the import must be lazy, inside the opt-in guard"


def test_a_failed_enrichment_call_does_not_crash_the_scan():
    """bg_worker.py wraps the whole call in try/except -- a scan must complete
    and save its findings even if enrichment blows up for an unrelated reason
    (e.g. the LLM server is down)."""
    import inspect
    from src.core import bg_worker
    src = inspect.getsource(bg_worker._run_fast_technical_vapt_bg)
    enrich_block = src[src.index("if ai_recommendations and all_findings:"):]
    enrich_block = enrich_block[:enrich_block.index("# Update database")]
    assert "try:" in enrich_block and "except Exception" in enrich_block
