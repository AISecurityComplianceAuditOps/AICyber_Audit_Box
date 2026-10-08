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
        # Count findings in the prompt by counting bracketed indices, and
        # answer each one (a finding left unanswered is asked again alone).
        import json as _json
        import re
        n = len(re.findall(r"^\[\d+\]", prompt, re.MULTILINE))
        calls.append(n)
        return _json.dumps({"remediations": {str(i): {"remediation": "Apply the vendor patch now.",
                                                      "actionable": "Upgrade the package today."}
                                             for i in range(n)}})

    findings = [_finding(title=f"Finding {i}") for i in range(20)]
    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake_query):
        enrich_remediations(findings, model="x", timeout=5)
    assert all(c <= mod._BATCH_SIZE for c in calls)
    assert sum(calls) == 20


def test_empty_findings_list_is_a_no_op():
    assert enrich_remediations([], model="x") == []


def test_a_failed_batch_does_not_stop_later_batches_and_is_retried():
    """Two batches; the first call raises. The other batch is still enriched,
    and the failed one is asked again at the end instead of keeping the
    parser's text."""
    import src.core.parsers.remediation_llm as mod
    calls = {"n": 0}

    def _fake_query(prompt, model, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("first call fails")
        n = len(__import__("re").findall(r"^\[\d+\]", prompt, __import__("re").MULTILINE))
        return __import__("json").dumps({"remediations": {
            str(i): "Enriched with a specific remediation for this finding." for i in range(n)}})

    findings = [_finding(title=f"F{i}") for i in range(mod._BATCH_SIZE + 1)]
    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake_query):
        enrich_remediations(findings, model="x", timeout=5)
    assert all(f["remediation"] != GENERIC for f in findings)
    assert enrich_remediations.last_failed_batches == 0


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


# ── Grouping: only identical findings share an answer ────────────────────────

def _answer_each_by_title(prompts):
    """A fake LLM that answers every finding with its own title, so a copied
    answer is visible as the wrong title."""
    import json
    import re as _re

    def _fake(prompt, *a, **kw):
        prompts.append(prompt)
        titles = dict(_re.findall(r"^\[(\d+)\] Title: (.*)$", prompt, _re.MULTILINE))
        return json.dumps({"remediations": {
            i: {"remediation": f"Fix for {t} in its own code path.",
                "actionable": f"Developer steps for {t} only."} for i, t in titles.items()}})
    return _fake


def test_every_distinct_finding_gets_its_own_answer():
    """A delivered report gave 14 of 16 Burp findings the SQL-injection fix of
    the first: every Burp PDF finding had plugin id "burp-pdf" and no CVE, so
    the whole report was one group and one answer was copied onto all of it."""
    titles = ["SQL injection (/catalog/filter [category parameter])",
              "SQL injection (/catalog/product/stock [request body])",
              "XML external entity injection",
              "Cross-site scripting (reflected) (/catalog/search/2 [term parameter])",
              "Strict transport security not enforced"]
    findings = [_finding(title=t, source_tool="Burp Suite", plugin_id="burp-pdf",
                         cve_list=["CWE-89"] if t.startswith("SQL") else [])
                for t in titles]
    prompts = []
    with mock.patch("src.core.llm_client.query_llm", side_effect=_answer_each_by_title(prompts)):
        enrich_remediations(findings)
    for f in findings:
        assert f["remediation"] == f"Fix for {f['title']} in its own code path.", f["title"]
        assert f["remediation_actionable"] == f"Developer steps for {f['title']} only."


def test_one_finding_on_many_hosts_is_asked_once_and_names_no_host():
    findings = [_finding(title="Nmap: Weak Cipher Suites Supported (443/tcp)", source_tool="Nmap",
                         target=f"10.0.0.{n}") for n in (5, 6, 7)]
    prompts = []
    with mock.patch("src.core.llm_client.query_llm", side_effect=_answer_each_by_title(prompts)):
        enrich_remediations(findings)
    body = "\n".join(prompts)
    assert body.count("Title: Nmap: Weak Cipher Suites Supported") == 1
    assert "do NOT name a specific host" in body
    assert len({f["remediation"] for f in findings}) == 1
    assert all("_group_size" not in f for f in findings)


# ── asked again, one at a time, when the answer was unusable ─────────────────

def _answer(n, text="Disable Telnet on port 23 and use SSH instead."):
    import json as _json
    return _json.dumps({"remediations": {str(i): {"remediation": text, "actionable": "systemctl disable telnet.socket"}
                                         for i in range(n)}})


def _count(prompt):
    import re
    return len(re.findall(r"^\[\d+\]", prompt, re.MULTILINE))


def test_an_unreadable_batch_reply_is_asked_again_one_finding_at_a_time():
    calls = []

    def _fake(prompt, model, **kw):
        n = _count(prompt)
        calls.append(n)
        return "Sure! {remediations: [broken" if n > 1 else _answer(1)

    findings = [_finding(title=f"Telnet {i}", target=f"10.0.0.{i}") for i in range(4)]
    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake):
        enrich_remediations(findings, model="x", timeout=5)
    assert calls == [4, 1, 1, 1, 1]
    assert all(f["remediation"] != GENERIC for f in findings)
    assert enrich_remediations.last_failed_batches == 0


def test_only_the_findings_the_reply_left_out_are_asked_again():
    calls = []

    def _fake(prompt, model, **kw):
        n = _count(prompt)
        calls.append(n)
        if n == 1:
            return _answer(1)
        import json as _json
        return _json.dumps({"remediations": {"0": {"remediation": "Disable Telnet on port 23 now.",
                                                   "actionable": "systemctl disable telnet"}}})

    findings = [_finding(title=f"Telnet {i}", target=f"10.0.0.{i}") for i in range(3)]
    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake):
        enrich_remediations(findings, model="x", timeout=5)
    assert calls == [3, 1, 1]
    assert all(f["remediation"] != GENERIC for f in findings)


def test_a_call_that_failed_is_retried_alone_at_the_end():
    """A model that stopped responding: not asked one finding at a time (that
    only multiplies the wait), but the whole batch is asked again once the
    others are done, up to _RETRY_ATTEMPTS times."""
    import src.core.parsers.remediation_llm as mod
    calls = []

    def _fake(prompt, model, **kw):
        calls.append(_count(prompt))
        raise TimeoutError("llama-server did not answer")

    findings = [_finding(title=f"Telnet {i}", target=f"10.0.0.{i}") for i in range(4)]
    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake):
        enrich_remediations(findings, model="x", timeout=5)
    assert calls == [4] * (1 + mod._RETRY_ATTEMPTS)
    assert all(f["remediation"] == GENERIC for f in findings)
    assert enrich_remediations.last_failed_batches == 1


def test_a_call_that_recovers_on_retry_is_enriched():
    calls = []

    def _fake(prompt, model, **kw):
        calls.append(_count(prompt))
        if len(calls) == 1:
            raise TimeoutError("llama-server did not answer")
        return _answer(_count(prompt))

    findings = [_finding(title=f"Telnet {i}", target=f"10.0.0.{i}") for i in range(4)]
    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake):
        enrich_remediations(findings, model="x", timeout=5)
    assert calls == [4, 4]
    assert all(f["remediation"] != GENERIC for f in findings)
    assert enrich_remediations.last_failed_batches == 0


def test_a_finding_that_still_gets_nothing_is_counted_as_failed():
    def _fake(prompt, model, **kw):
        return "no JSON here at all"

    findings = [_finding(title=f"Telnet {i}", target=f"10.0.0.{i}") for i in range(2)]
    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake):
        enrich_remediations(findings, model="x", timeout=5)
    assert all(f["remediation"] == GENERIC for f in findings)
    assert enrich_remediations.last_failed_batches == 1


# ── VAPT: recommendation and developer steps as points ───────────────────────
# Reviewers asked for the fix as points with enough detail to act on, not 2-4
# sentences of prose. VAPT scans pass pointwise=True; PQC scans (and any other
# caller) keep the prose prompt and the text exactly as the model wrote it.

import html
import io
import json as _json
import os as _os
import re as _re

from src.core.parsers.remediation_llm import (_POINTWISE_PROMPT_TEMPLATE,
                                              _PROMPT_TEMPLATE,
                                              _as_numbered_steps, _as_points)

SQLI_STEPS = ("1. Replace string-built SQL for `category` with parameterized queries. "
              "2. Validate `category` against an allow-list of known values "
              "3. Re-test /catalog/filter with Burp to confirm the fix.")
SQLI_STORED = ("1. Replace string-built SQL for `category` with parameterized queries.\n"
               "2. Validate `category` against an allow-list of known values.\n"
               "3. Re-test /catalog/filter with Burp to confirm the fix.")
SQLI_POINTS = ("1. The `category` parameter on /catalog/filter is put into a SQL query unsafely. "
               "2. Rewrite that query with prepared statements "
               "3. Accept only known category values. "
               "4. This stops attackers reading or changing data through this parameter.")
SQLI_POINTS_STORED = ("- The `category` parameter on /catalog/filter is put into a SQL query unsafely.\n"
                      "- Rewrite that query with prepared statements.\n"
                      "- Accept only known category values.\n"
                      "- This stops attackers reading or changing data through this parameter.")


def _pw_reply(actionable, remediation=SQLI_POINTS):
    return _json.dumps({"remediations": {"0": {"remediation": remediation, "actionable": actionable}}})


def _run(reply, pointwise, finding=None):
    prompts = []
    f = finding or _finding()
    with mock.patch("src.core.llm_client.query_llm",
                    side_effect=lambda p, *a, **k: prompts.append(p) or reply):
        enrich_remediations([f], model="x", timeout=5, pointwise=pointwise)
    return f, prompts


def test_vapt_asks_for_points_and_numbered_steps():
    _f, prompts = _run(_pw_reply(SQLI_STEPS), pointwise=True)
    assert prompts[0] == _POINTWISE_PROMPT_TEMPLATE.format(n=1, findings_block=_format_finding_block(0, _finding()))
    assert "3 to 4 points for the report reader" in prompts[0]
    assert "3 to 5 numbered developer steps" in prompts[0]
    # A config edit without the restart that applies it leaves the finding open
    # (seen live: Redis steps edited redis.conf and went straight to re-test).
    assert "a later step applies it (restart or reload that service)" in " ".join(prompts[0].split())


def test_the_pointwise_prompt_keeps_every_grounding_rule():
    """More detail must not mean invented detail: the rules against invented
    CVEs, versions and products, and the sparse-evidence rule, are all there."""
    for rule in ("Do not invent a CVE, version number, or fact",
                 "Do not change or restate the severity",
                 "too sparse to say anything specific",
                 "Read each finding's evidence",
                 'mark any example with "e.g."'):
        assert rule in _POINTWISE_PROMPT_TEMPLATE, rule


def test_pqc_and_other_callers_keep_the_prose_prompt_and_text():
    f, prompts = _run(_pw_reply(SQLI_STEPS), pointwise=False)
    assert prompts[0] == _PROMPT_TEMPLATE.format(n=1, findings_block=_format_finding_block(0, _finding()))
    assert "1 to 4 sentences" in prompts[0]
    assert f["remediation"] == SQLI_POINTS                               # stored as written
    assert f["remediation_actionable"] == SQLI_STEPS


def test_vapt_points_and_steps_are_stored_one_per_line():
    f, _p = _run(_pw_reply(SQLI_STEPS), pointwise=True)
    assert f["remediation"] == SQLI_POINTS_STORED
    assert f["remediation_actionable"] == SQLI_STORED


def test_steps_sent_as_a_json_list_are_numbered():
    f, _p = _run(_pw_reply(["Set `requirepass` in redis.conf", "Bind Redis to 127.0.0.1",
                            "Re-scan port 6379 to confirm"]), pointwise=True)
    assert f["remediation_actionable"] == ("1. Set `requirepass` in redis.conf.\n"
                                           "2. Bind Redis to 127.0.0.1.\n"
                                           "3. Re-scan port 6379 to confirm.")


def test_points_sent_as_a_json_list_are_bulleted():
    f, _p = _run(_pw_reply(SQLI_STEPS, remediation=["Redis on port 6379 accepts clients without a password",
                                                    "Enable `requirepass`"]), pointwise=True)
    assert f["remediation"] == "- Redis on port 6379 accepts clients without a password.\n- Enable `requirepass`."


def test_prose_is_kept_as_written():
    f, _p = _run(_pw_reply("Run: systemctl disable telnetd; ufw deny 23/tcp.",
                           remediation="Disable the Telnet service on port 23."), pointwise=True)
    assert f["remediation"] == "Disable the Telnet service on port 23."
    assert f["remediation_actionable"] == "Run: systemctl disable telnetd; ufw deny 23/tcp."


@pytest.mark.parametrize("raw, stored", [
    # a number inside a step is not the next step
    ("1. Set MaxAuthTries to 2. 2. Restart sshd. 3. Re-scan port 22.",
     "1. Set MaxAuthTries to 2.\n2. Restart sshd.\n3. Re-scan port 22."),
    ("1. Upgrade OpenSSH to 9. Then restart it. 2. Re-scan port 22.",
     "1. Upgrade OpenSSH to 9. Then restart it.\n2. Re-scan port 22."),
    ("1. Disable TLS 1.0 and TLS 1.1 in nginx 2. Reload nginx 3. Re-run the TLS scan",
     "1. Disable TLS 1.0 and TLS 1.1 in nginx.\n2. Reload nginx.\n3. Re-run the TLS scan."),
    # one per line, "1)" numbering, "-" bullets, a heading before step 1
    ("1) Remove the vsftpd 2.3.4 package\n2) Install the vendor's patched release\n3) Re-scan port 21",
     "1. Remove the vsftpd 2.3.4 package.\n2. Install the vendor's patched release.\n3. Re-scan port 21."),
    ("- Enable HSTS\n- Redirect HTTP to HTTPS\n- Re-test the site",
     "1. Enable HSTS.\n2. Redirect HTTP to HTTPS.\n3. Re-test the site."),
    ("Steps: 1. Add the header. 2. Re-test.", "1. Add the header.\n2. Re-test."),
    ("Patch first. 1. Add the header. 2. Re-test.", "Patch first.\n1. Add the header.\n2. Re-test."),
    # already in the stored shape: unchanged
    (SQLI_STORED, SQLI_STORED),
])
def test_step_splitting(raw, stored):
    assert _as_numbered_steps(raw) == stored


@pytest.mark.parametrize("raw, stored", [
    (SQLI_POINTS, SQLI_POINTS_STORED),
    ("- Enable HSTS on the site\n- Redirect HTTP to HTTPS", "- Enable HSTS on the site.\n- Redirect HTTP to HTTPS."),
    ("Summary: 1. Fix it here. 2. Harden it.", "- Fix it here.\n- Harden it."),
    ("Patch first. 1. Fix it here. 2. Harden it.", "- Patch first.\n- Fix it here.\n- Harden it."),
    (SQLI_POINTS_STORED, SQLI_POINTS_STORED),                       # already stored: unchanged
])
def test_point_splitting(raw, stored):
    assert _as_points(raw) == stored


@pytest.mark.parametrize("raw", ["", None, "Upgrade to TLS 1.2 now. Use AES-GCM.", "1. Only one step here."])
def test_fewer_than_two_is_left_alone(raw):
    assert _as_numbered_steps(raw) == (raw or "")
    assert _as_points(raw) == (raw or "")


def test_the_one_at_a_time_retry_also_uses_the_pointwise_prompt():
    prompts = []

    def _fake(prompt, model, **kw):
        prompts.append(prompt)
        n = len(_re.findall(r"^\[\d+\]", prompt, _re.MULTILINE))
        return "Sure! {remediations: [broken" if n > 1 else _pw_reply(SQLI_STEPS)

    findings = [_finding(title=f"Telnet {i}", target=f"10.0.0.{i}") for i in range(2)]
    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake):
        enrich_remediations(findings, model="x", timeout=5, pointwise=True)
    assert len(prompts) == 3 and all("3 to 5 numbered developer steps" in p for p in prompts)
    assert all(f["remediation_actionable"] == SQLI_STORED for f in findings)
    assert all(f["remediation"] == SQLI_POINTS_STORED for f in findings)


def test_vapt_asks_two_findings_per_call():
    """Pointwise answers run about three times longer; four per call nears the
    time budget on a CPU-only box."""
    counts = []

    def _fake(prompt, model, **kw):
        n = len(_re.findall(r"^\[\d+\]", prompt, _re.MULTILINE))
        counts.append(n)
        return _json.dumps({"remediations": {str(i): {"remediation": SQLI_POINTS, "actionable": SQLI_STEPS}
                                             for i in range(n)}})

    findings = [_finding(title=f"Finding {i}", target=f"10.0.0.{i}") for i in range(5)]
    with mock.patch("src.core.llm_client.query_llm", side_effect=_fake):
        enrich_remediations(findings, model="x", timeout=5, pointwise=True)
    assert sorted(counts) == [1, 2, 2]


def test_the_worker_asks_for_points_for_vapt_only():
    import inspect
    from src.core import bg_worker
    src = inspect.getsource(bg_worker._run_fast_technical_vapt_bg)
    block = src[src.index("if ai_recommendations and all_findings:"):]
    block = block[:block.index("# Update database")]
    assert 'pointwise=(_dispatch_framework == "vapt")' in block
    assert '_dispatch_framework = "pqc" if "PQC" in _fw_upper else "vapt"' in src


# The finding card (formatRemediationSteps in app.js) starts a new step only
# after a full stop: /([.!?])\s+(\d{1,2})\.\s+/. Mirrored here, and the JS
# checked for that exact rule, so the stored shape and the card cannot drift.
_APP_JS = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                        "src", "api", "static", "app.js")


def _card_steps(text):
    marked = _re.sub(r"([.!?])\s+(\d{1,2})\.\s+", lambda m: f"{m.group(1)} \x00{m.group(2)}. ", text)
    marked = _re.sub(r":\s+(\d{1,2})\.\s+(?=[A-Z])", lambda m: f": \x00{m.group(1)}. ", marked)
    marked = _re.sub(r"^(\d{1,2})\.\s+", lambda m: f"\x00{m.group(1)}. ", marked, count=1)
    return [p.strip() for p in marked.split("\x00") if p.strip()]


def test_the_card_splits_the_stored_steps_where_they_are():
    with open(_APP_JS, encoding="utf-8") as fh:
        js = fh.read()
    assert r".replace(/([.!?])\s+(\d{1,2})\.\s+/g, `$1 ${delim}$2. `)" in js
    for raw in (SQLI_STEPS,
                "1. Set `ssl_protocols TLSv1.2 TLSv1.3;` in nginx 2. Reload nginx 3. Re-scan port 443",
                ["Upgrade PyJWT from 2.13.0 to the vendor's patched release",
                 "Run `pip install -U PyJWT`", "Re-run dependency-check"]):
        stored = _as_numbered_steps(raw)
        assert _card_steps(stored) == stored.splitlines(), stored


# The VAPT card lists a recommendation whose every line starts with "- "
# (formatVaptRecommendation in app.js); anything else, such as a scanner's own
# advice in parser mode, still goes to formatRemediationSteps.
def _card_points(text):
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) >= 2 and all(ln.startswith("- ") for ln in lines):
        return [ln[2:].strip() for ln in lines]
    return None


def _app_js():
    with open(_APP_JS, encoding="utf-8") as fh:
        return fh.read()


def test_the_vapt_card_lists_the_stored_points():
    js = _app_js()
    assert "function formatVaptRecommendation(text, color)" in js
    assert 'lines.every(l => l.startsWith("- "))' in js
    assert "${_vRem ? formatVaptRecommendation(_remed, '#2563eb') : formatRemediationSteps(_remed, '#2563eb')}" in js
    for raw in (SQLI_POINTS, ["Redis on port 6379 needs no password", "Enable `requirepass`"]):
        stored = _as_points(raw)
        assert _card_points(stored) == [ln[2:] for ln in stored.splitlines()], stored


def test_a_scanners_own_advice_is_not_taken_for_points():
    burp = ("[Remediation]\nThe most effective way to prevent SQL injection attacks is to use "
            "parameterized queries (also known as prepared statements) for all database access.")
    assert _card_points(burp) is None


def test_the_vapt_copy_buttons_survive_line_breaks_and_apostrophes():
    """vaptCopyArg: escapeHtml(JSON.stringify(text)). The browser decodes the
    attribute, then runs the handler: the argument must be one valid string
    literal that gives back the text exactly."""
    js = _app_js()
    assert 'return escapeHtml(JSON.stringify(String(text || "")));' in js
    assert "writeText(${_vRem ? vaptCopyArg(_remed) :" in js
    assert "writeText(${_vRem ? vaptCopyArg(_remedActionable) :" in js
    text = SQLI_POINTS_STORED + "\n- Install the vendor's patched release of C:\\Apps <v2> & \"cfg\"."
    arg = html.escape(_json.dumps(text, ensure_ascii=False), quote=True)    # what the page writes
    handler_arg = html.unescape(arg)                                         # what the handler runs
    assert "\n" not in handler_arg and handler_arg.startswith('"') and handler_arg.endswith('"')
    assert _json.loads(handler_arg) == text


def _vapt_row(steps, recommendation="Use parameterized queries."):
    return [dict(control_id="VAPT-4", title="SQL injection", severity="HIGH", status="Non-Compliant",
                 final_result="NON_COMPLIANT", description="d", target="https://shop.test/",
                 evidence_snippet="proof", recommendation=recommendation,
                 remediation_actionable=steps)]


def test_the_pdf_prints_one_point_and_one_step_per_line():
    from pypdf import PdfReader
    from src.core.report_exporter import export_pdf_report
    out = export_pdf_report("t", _vapt_row(SQLI_STORED, SQLI_POINTS_STORED), [], "FINAL", audit_type="vapt")
    text = "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(out)).pages)
    # Each point starts its own line behind a drawn bullet (so without its "- "),
    # each step behind its number (test_vapt_recommendation_points.py).
    points = [ln[2:] for ln in SQLI_POINTS_STORED.splitlines()]
    for line in points + SQLI_STORED.splitlines():
        assert _re.search(r"^" + _re.escape(line[:30]), text, _re.MULTILINE), line


def test_the_docx_prints_one_point_and_one_step_per_line():
    from docx import Document
    from src.core.report_exporter import export_docx_report
    d = Document(io.BytesIO(export_docx_report("t", _vapt_row(SQLI_STORED, SQLI_POINTS_STORED), [], "FINAL",
                                               audit_type="vapt")))
    texts = [p.text for p in d.paragraphs]
    # One paragraph per point (a bullet) and per step (its number), with a
    # hanging indent -- test_vapt_recommendation_points.py.
    for ln in SQLI_POINTS_STORED.splitlines():
        assert "•\t" + ln[2:] in texts, ln
    for ln in SQLI_STORED.splitlines():
        num, body = ln.split(". ", 1)
        assert f"{num}.\t{body}" in texts, ln
