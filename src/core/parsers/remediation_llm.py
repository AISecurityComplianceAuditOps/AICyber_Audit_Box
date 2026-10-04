# -*- coding: utf-8 -*-
"""
Hybrid parser+LLM enrichment for VAPT/PQC remediation text.

The deterministic parsers (nmap_parser.py, qualys_parser.py, etc.) are correct
and stay untouched: severity, CVE list, CVSS score, control mapping, title,
evidence -- all of that comes straight from the scanner's own output and this
module never writes to any of it.

Operates on the plain dict shape bg_worker.py already builds (f_dict, i.e. a
Finding run through .to_dict()/asdict()), not on Finding objects directly --
by the point findings are collected into all_findings, they have already been
converted, and re-wrapping them back into Finding just to unwrap again would
be pure overhead with no benefit.

What is fixed here is narrower and more specific: two text fields are the SAME
literal sentence on every finding regardless of what was actually found.
"remediation" is the clear case in nmap_parser.py -- "Investigate service
misconfiguration and apply vendor patches/hardening." is written three times
in that file, verbatim, for every open-port finding it produces, whether the
port is a stale Telnet service or a modern web server with one weak cipher.
"remediation_actionable" has the same problem one level down: it comes from
control_mapper.py::get_actionable_remediation(), a ~35-keyword template table
-- every finding matching a given keyword (e.g. every "telnet" finding) gets
the identical developer-facing template text. Neither is a mitigation step
grounded in what was actually found; both are placeholders.

Called ONLY when the auditor opts in (ai_recommendations=True on the request).
The parser path stays exactly as fast and exactly as deterministic as it is
today -- and stays advertised that way -- unless this is explicitly switched on,
because turning every "instant, zero AI compute" scan into an LLM-backed one by
default would be the opposite of what that mode promises.

Failure mode is fixed at the top: any exception, timeout, or malformed response
anywhere in this module means the ORIGINAL parser-generated remediation is kept
untouched. This function is never allowed to make a finding worse by running.
"""
import json
import re
import os
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Dict, List

# Findings per LLM call. This was 8, which on a CPU-only box produces ~2000
# output tokens per call -- roughly 15 minutes at the ~1.7 tok/s a 12B model
# manages here, against query_llm()'s default budget of max(600, active*180)
# seconds. Batches therefore ran out of time, and because a failed batch keeps
# its parser text silently, the whole feature looked exactly like leaving it
# switched off: measured 22/22 byte-identical recommendations across an AI-on
# and an AI-off scan of the same evidence. Four keeps each generation short
# enough to finish inside the budget.
_BATCH_SIZE = int(os.environ.get("REMEDIATION_BATCH_SIZE", "4"))

_MAX_EVIDENCE_CHARS = 400
_MAX_DESCRIPTION_CHARS = 400

# How many batches run at once: this scan's fair share of the model server's
# slots (llm_capacity.fair_share), recomputed after every batch. It was a fixed
# 4, which on a 4-core machine split the CPU four ways and slowed each batch
# until one ran into the 30-minute request ceiling (measured: 1 of 17 batches,
# one auditor). Batches are no longer cut off for being slow -- query_llm with
# no_time_limit waits while the model keeps writing -- and a batch that fails
# outright is retried, alone, after the others.
_MAX_PARALLEL_BATCHES = int(os.environ.get("REMEDIATION_MAX_PARALLEL", "64"))
_RETRY_ATTEMPTS = int(os.environ.get("REMEDIATION_RETRY_ATTEMPTS", "3"))
_RETRY_DELAY_SEC = float(os.environ.get("REMEDIATION_RETRY_DELAY_SEC", "20"))

_PROMPT_TEMPLATE = """You are a senior penetration tester writing a vulnerability
report. You will be given {n} findings, each with its title, severity, CVE(s)
if any, and the raw evidence that was actually observed.

For EACH finding, write TWO things. Both must be grounded in what is actually
shown for THAT finding: name the specific service, port, package, or
configuration value that appears in its own evidence, not a generic
instruction that would apply to any finding of that type.
  1. "remediation" -- the recommended fix, for an auditor/report reader, 1 to
     3 sentences.
  2. "actionable" -- concrete, developer-facing steps to implement that fix:
     specific commands, config keys/values, the package or version to upgrade
     to, or the service to disable/restart. 1 to 4 sentences.

RULES, followed exactly:
  - Do not invent a CVE, version number, or fact that is not present in the
    finding's own evidence or title. If the evidence does not say which
    software is running, say to identify the service first rather than
    guessing a product name.
  - Do not change or restate the severity -- you are writing remediation only.
  - If a finding's evidence is too sparse to say anything specific, write
    GENERAL hardening guidance for the affected port/service class named in
    the title, and say plainly that the specific software could not be
    identified from the evidence provided. Do not fabricate specificity that
    is not there.
  - Output ONLY a JSON object, no other text, in exactly this shape:
    {{"remediations": {{"0": {{"remediation": "...", "actionable": "..."}}, ...}}}}
    keyed by the finding's index below, as a string.

FINDINGS:
{findings_block}
"""

# VAPT scans (pointwise=True). Reviewers asked for the fix as points with
# enough detail to act on: the prompt above gives 2-4 sentences of prose for
# each field. The detail comes from the shape asked for (3-4 recommendation
# points; 3-5 steps, each with the exact command or config and a short reason),
# and every point still names what was found in that finding's own evidence.
# PQC scans keep the prompt above.
_POINTWISE_PROMPT_TEMPLATE = """You are a senior penetration tester writing the fix section of a
vulnerability report. You will be given {n} findings, each with its title,
severity, CVE(s) if any, and the raw evidence that was actually observed.

Read each finding's evidence, then write TWO point-wise answers for it. Both
must be about THAT finding: name the exact endpoint, parameter, header, port,
service, package or configuration value that appears in its own title or
evidence (a NOTE given with a finding overrides this), not a generic
instruction that would fit any finding of that type.
  1. "remediation" -- 3 to 4 points for the report reader, written as
     "1. ... 2. ... 3. ...", each ONE full sentence of at most 25 words:
       - what is wrong, and exactly where;
       - the fix;
       - any extra hardening that applies to this finding;
       - the risk to this system that the fix removes.
  2. "actionable" -- 3 to 5 numbered developer steps, written as
     "1. ... 2. ... 3. ...", each at most 35 words: the action, the exact
     command, config line, header value or package name in backticks, and a
     short reason. When a step changes a configuration file or installs a
     package, a later step applies it (restart or reload that service). The
     last step says how to re-test the same endpoint, port or package, and
     what result confirms the fix.

KEEP IT USEFUL:
  - No filler. Never write "follow best practices", "consult the
    documentation", "consider", "ensure security", "regularly monitor" or "as
    appropriate". Every point and step is specific to this finding.
  - No textbook background about the vulnerability class.
  - If the evidence does not identify the language, framework or product,
    mark any example with "e.g." and keep it generic; never state that the
    target runs it.

RULES, followed exactly:
  - Do not invent a CVE, version number, or fact that is not present in the
    finding's own evidence or title. If the fixed version is not given, write
    "the vendor's patched release" instead of guessing a number. If the
    evidence does not say which software is running, the first step is to
    identify the service, not a guessed product name.
  - Do not change or restate the severity -- you are writing remediation only.
  - If a finding's evidence is too sparse to say anything specific, give
    GENERAL hardening points and steps for the affected port/service class
    named in the title, and say plainly in the first point that the specific
    software could not be identified from the evidence provided.
  - Output ONLY a JSON object, no other text, in exactly this shape:
    {{"remediations": {{"0": {{"remediation": "1. ... 2. ... 3. ...", "actionable": "1. ... 2. ... 3. ..."}}, ...}}}}
    keyed by the finding's index below, as a string.

FINDINGS:
{findings_block}
"""

# Findings per call for pointwise answers, which run about three times longer
# than the prose ones: at four per call a CPU-only box nears the 1800 s budget
# (see _BATCH_SIZE above for what a batch that runs out of time costs).
_POINTWISE_BATCH_SIZE = int(os.environ.get("REMEDIATION_POINTWISE_BATCH_SIZE", "2"))

# A step number: "2. " or "2) " at the start or after whitespace, followed by
# the step's first character (not another digit, so "set it to 2. 2. Restart"
# is one marker, not two). Only the NEXT number in sequence counts as a marker
# (see _split_numbered): "upgrade to 9. Then" inside step 1 does not start a step.
_STEP_MARK_RE = re.compile(r"(?:^|(?<=\s))(\d{1,2})[.)]\s+(?=[^\s\d])")
_BULLET_LINE_RE = re.compile(r"^\s*[-*•]\s+")


def _split_numbered(text):
    """(preamble, [steps]) for "1. a 2. b" written inline or one per line."""
    marks, want = [], 1
    for m in _STEP_MARK_RE.finditer(text):
        if int(m.group(1)) == want:
            marks.append(m)
            want += 1
    if len(marks) < 2:
        return "", []
    steps = [text[m.end():(marks[i + 1].start() if i + 1 < len(marks) else len(text))]
             for i, m in enumerate(marks)]
    return text[:marks[0].start()], steps


def _split_points(value):
    """(preamble, [points]) for points written inline ("1. a 2. b"), one per
    line, as "-" bullets, or as a JSON list; no points when there are fewer
    than two. A heading before the first point ("Steps:") is dropped."""
    if isinstance(value, (list, tuple)):
        preamble, points = "", [str(s) for s in value if str(s or "").strip()]
    else:
        text = str(value or "").strip()
        preamble, points = _split_numbered(text)
        if not points:
            lines = [ln for ln in text.splitlines() if ln.strip()]
            if len(lines) >= 2 and all(_BULLET_LINE_RE.match(ln) for ln in lines):
                points = [_BULLET_LINE_RE.sub("", ln) for ln in lines]
    points = [p for p in (re.sub(r"\s+", " ", p).strip() for p in points) if p]
    if len(points) < 2:
        return "", []
    preamble = re.sub(r"\s+", " ", preamble).strip()
    return ("" if preamble.endswith(":") else preamble), points


def _as_written(value):
    """Fewer than two points: prose stays prose, and nothing is dropped."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(re.sub(r"\s+", " ", str(s)).strip() for s in value if str(s or "").strip())
    return ""


def _full_stop(text):
    return text if text[-1] in ".!?" else text + "."


def _as_numbered_steps(value):
    """The model's developer steps as one numbered step per line:
    "1. Do this.\\n2. Do that." -- the shape the finding card splits into a
    numbered list (formatRemediationSteps in app.js splits after a full stop)
    and the PDF/DOCX print one step per line. A sentence before step 1 is kept
    as its own line."""
    preamble, steps = _split_points(value)
    if not steps:
        return _as_written(value)
    lines = [_full_stop(preamble)] if preamble else []
    return "\n".join(lines + [f"{i}. {_full_stop(s)}" for i, s in enumerate(steps, 1)])


def _as_points(value):
    """The model's recommendation as one "- " point per line: the VAPT finding
    card lists text whose every line starts with "- " (formatVaptRecommendation
    in app.js), and the PDF/DOCX print it as written."""
    preamble, points = _split_points(value)
    if not points:
        return _as_written(value)
    return "\n".join(f"- {_full_stop(p)}" for p in ([preamble] if preamble else []) + points)


def _clip(text, limit):
    text = str(text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "…"


def _format_finding_block(idx: int, f: Dict, instances: int = 1) -> str:
    cve_list = f.get("cve_list") or []
    cves = ", ".join(cve_list) if cve_list else "none"
    # The answer for a grouped finding is copied onto every other host it was
    # found on, so it must not name this one's host, IP or URL.
    shared = (f"\n    NOTE: this same finding was reported on {instances} targets. Write text that "
              f"is correct for all of them: do NOT name a specific host, IP address or URL."
              if instances > 1 else "")
    return (
        f"[{idx}] Title: {f.get('title', '')}\n"
        f"    Severity: {f.get('severity', '')}   CVE(s): {cves}   Target: {f.get('target') or 'n/a'}\n"
        f"    Evidence: {_clip(f.get('evidence', ''), _MAX_EVIDENCE_CHARS)}\n"
        f"    Description: {_clip(f.get('description', ''), _MAX_DESCRIPTION_CHARS)}"
        f"{shared}"
    )


# A backslash JSON does not permit: one not followed by " \\ / b f n r t,
# nor by a u with four hex digits after it.
#
# Every alternative sits inside the lookahead so the match is the BACKSLASH
# ALONE. An earlier version consumed the character too, which turned
# C:\users into C:\sers -- a repair that silently corrupted the text it
# was rescuing.
_INVALID_ESCAPE_RE = re.compile(r'\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})')


def _extract_json_object(raw: str):
    """Same tolerance the ISO chain already applies to LLM output: strip a
    ```json fence if present, otherwise take the outermost {...}. A local model
    under load is not guaranteed to skip the fence even when told to."""
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty response")
    fenced = re.findall(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if fenced:
        text = fenced[0]
    if not (text.startswith("{") and text.endswith("}")):
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("no JSON object found in response")
        text = text[start:end + 1]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # A stray backslash, repaired rather than thrown away.
        #
        # JSON permits only a handful of escapes. A model writing remediation
        # text reaches for backslashes constantly and legitimately -- a Windows
        # path (C:\Program Files), a regex (\d+), an escape sequence it is
        # telling a developer to use -- and any one of them makes the whole
        # reply unparseable. Measured on a real scan: 25 of 61 batches lost
        # with ONE user on an idle machine, every one of them 'Invalid escape'.
        # Each failure discards the AI text for four findings and silently
        # falls back to the generic wording.
        #
        # Tried only after a normal parse has failed, so well-formed output is
        # never touched.
        try:
            return json.loads(_INVALID_ESCAPE_RE.sub(r'\\\\', text))
        except json.JSONDecodeError:
            # Still not JSON: read it by the shape the prompt asks for.
            return _salvage_remediations(text)


# The reply's own shape, for reading it when it is not valid JSON:
#   {"remediations": {"0": {"remediation": "...", "actionable": "..."}, ...}}
_BLOCK_START_RE = re.compile(r'"(\d+)"\s*:\s*\{')
_FIELD_START_RE = {k: re.compile(r'"%s"\s*:\s*"' % k) for k in ("remediation", "actionable")}
_NEXT_FIELD_RE = re.compile(r'"\s*,\s*"(?:remediation|actionable)"\s*:')
_ENTRY_END_RE = re.compile(r'"\s*\}')


def _decode_loose_string(body):
    """A JSON string body written loosely -- a bare quote, a stray backslash, a
    raw line break -- read as JSON would read it. The text as written when even
    that fails."""
    s = _INVALID_ESCAPE_RE.sub(r'\\\\', body)
    s = re.sub(r'(?<!\\)"', r'\\"', s)
    s = s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    s = re.sub(r"[\x00-\x1f]", " ", s)
    try:
        return json.loads('"' + s + '"')
    except ValueError:
        return body


def _salvage_remediations(text):
    """Each finding's two fields, found by the reply's known shape.

    The backslash repair above left one common failure: a quote inside the
    text. Asked for remediation, the model writes 'Set the "Secure" and
    "HttpOnly" flags' -- one unescaped quote ends the JSON string, and the
    whole reply was discarded: at a customer, "JSONDecodeError: Expecting ','
    delimiter", four findings back to the generic text. A reply cut off
    mid-finding was lost the same way.

    A field's text runs to the quote that is followed by the other field's key
    or by the closing brace, so quotes inside it are kept. Entries the reply
    finished are returned; one it did not is left out, and its finding is
    asked again on its own (see _enrich_batch).
    """
    starts = list(_BLOCK_START_RE.finditer(text))
    out = {}
    for i, m in enumerate(starts):
        block = text[m.end():starts[i + 1].start() if i + 1 < len(starts) else len(text)]
        entry = {}
        for key, rx in _FIELD_START_RE.items():
            f = rx.search(block)
            if not f:
                continue
            nxt = _NEXT_FIELD_RE.search(block, f.end())
            if nxt:
                end = nxt.start()
            else:
                closes = list(_ENTRY_END_RE.finditer(block, f.end()))
                if not closes:
                    continue            # cut off before this field ended
                end = closes[-1].start()
            entry[key] = _decode_loose_string(block[f.end():end])
        if entry:
            out[m.group(1)] = entry
    if not out:
        raise ValueError("reply is not JSON and has no readable finding entries")
    return {"remediations": out}


def _enrich_batch(batch: List[Dict], model: str, session_id=None, timeout=None,
                  pointwise=False) -> bool:
    """Mutates `.remediation` on the findings in `batch` in place. Never raises
    -- a finding the model gives no usable text keeps its original text, and
    the caller moves on rather than aborting the run. True when every finding
    in the batch got the model's text.

    When the model ANSWERED but some findings got nothing usable from it (a
    reply that could not be read, or an entry missing or cut off), those are
    asked again one at a time: a one-finding reply is short, and one bad
    answer then costs one finding, not four. Not when the call itself failed
    -- a timeout or an unreachable server -- where asking again only multiplies
    the wait.
    """
    missing, answered = _ask_batch(batch, model, session_id=session_id, timeout=timeout,
                                   pointwise=pointwise)
    if missing and answered and len(batch) > 1:
        print(f"[REMEDIATION LLM] Asking again for {len(missing)} finding(s), "
              f"one at a time.", flush=True)
        missing = [f for f in missing
                   if _ask_batch([f], model, session_id=session_id, timeout=timeout,
                                 pointwise=pointwise)[0]]
    return not missing


def _ask_batch(batch: List[Dict], model: str, session_id=None, timeout=None,
               pointwise=False):
    """One call for `batch`. Returns (the findings that got no remediation
    text, whether the model answered at all)."""
    from src.core.llm_client import query_llm

    findings_block = "\n".join(_format_finding_block(i, f, f.get("_group_size", 1))
                               for i, f in enumerate(batch))
    template = _POINTWISE_PROMPT_TEMPLATE if pointwise else _PROMPT_TEMPLATE
    prompt = template.format(n=len(batch), findings_block=findings_block)

    try:
        raw = query_llm(
            prompt, model, num_ctx=8192, temperature=0.1,
            # No ceiling unless a caller sets one: the request waits while the
            # model keeps writing and fails only if it falls silent.
            timeout=timeout, no_time_limit=timeout is None,
            session_id=session_id,
            # query_llm()'s DEFAULT stop list includes "```", tuned for the
            # ISO/VAPT XML-tag generator chains where a fence never appears in
            # a valid response. Here the model is EXPECTED to wrap its answer
            # in a ```json fence (the prompt asks for JSON, and this model's
            # chat template opens every reply with a `<|channel>thought`
            # header before its real content) -- so the default list matched
            # the model's own opening fence and truncated the response to
            # nothing, every single time, regardless of format= or timeout.
            # Confirmed by direct comparison: identical prompt, same model,
            # only this stop list changed -- 28-char empty response became a
            # complete, grounded answer. format="json" (grammar-constrained
            # decoding) is intentionally NOT used either: it showed the same
            # empty-response failure, and the prompt instruction plus
            # _extract_json_object's tolerant fence-stripping is sufficient.
            stop=["<end_of_turn>", "<eos>", "<|im_end|>", "</s>"],
        )
    except Exception as e:
        print(f"[REMEDIATION LLM] Batch of {len(batch)} finding(s) not enriched, "
              f"keeping parser text: {type(e).__name__}: {e}", flush=True)
        return list(batch), False
    try:
        data = _extract_json_object(raw)
        remediations = data.get("remediations")
        if not isinstance(remediations, dict):
            raise ValueError("response missing a 'remediations' object")
    except Exception as e:
        print(f"[REMEDIATION LLM] Batch of {len(batch)} finding(s) not enriched, "
              f"keeping parser text: {type(e).__name__}: {e}", flush=True)
        return list(batch), True

    missing = []
    for i, f in enumerate(batch):
        entry = remediations.get(str(i))
        # Tolerate a bare string too (some models flatten the nested object
        # despite the prompt) -- treated as "remediation" only, since that was
        # the original single-field contract and is the more important half.
        if isinstance(entry, dict):
            rem_raw, act_raw = entry.get("remediation"), entry.get("actionable")
            if pointwise:
                rem_text = _as_points(rem_raw).strip()
                act_text = _as_numbered_steps(act_raw).strip()
            else:
                rem_text = str(rem_raw or "").strip()
                act_text = str(act_raw or "").strip()
        else:
            rem_text = str(entry or "").strip()
            act_text = ""
        # A blank or suspiciously short reply is treated as a failure for that
        # ONE field on that ONE finding, not the whole batch -- the other
        # findings (and the other field on this same finding) may well be
        # fine, and the fallback stays the original deterministic text either
        # way, so there is nothing to lose by trying.
        if len(rem_text) >= 15:
            f["remediation"] = rem_text
        else:
            missing.append(f)
        if len(act_text) >= 15:
            f["remediation_actionable"] = act_text

    return missing, True


def _vuln_type_key(f: Dict) -> str:
    """Groups findings by VULNERABILITY TYPE, deliberately ignoring host/target
    -- the opposite of Finding.dedup_key() (finding_schema.py), which is
    host-aware on purpose so the same issue on two different servers stays two
    separate report rows. That is correct for the report; it is wasteful for
    THIS module. The remediation sentence for "TLS 1.0 enabled" is the same
    text whether it is host A or host B -- asking the LLM to write it once per
    host is N calls for one answer. Grouping here (LLM cost only; the report
    still lists every host's own finding row untouched) asks it once per
    distinct vulnerability instead.

    Only IDENTICAL findings group: same tool, same title, same CVE/CWE list --
    one issue repeated on many hosts. The key used to be the CVE list alone, or
    tool + plugin id, with the title ignored. Every Burp PDF finding had the
    plugin id "burp-pdf" and, then, no CVE, so a whole report was ONE group: the
    LLM answered the first finding (SQL injection in the "category" parameter on
    /catalog/filter) and that answer was copied onto XXE, XSS, SSRF, HSTS and
    the rest -- 14 of 16 findings in a delivered report told developers to fix
    a different bug. Keyed on CWEs it would still have merged three SQL
    injections on three different endpoints under the first one's text.
    """
    cve_list = f.get("cve_list") or []
    clean_cves = sorted(set(str(c).strip().upper() for c in cve_list if c and str(c).strip()))
    tool = str(f.get("source_tool") or "generic").lower().strip()
    title = re.sub(r"\s+", " ", str(f.get("title") or "").strip().lower())
    return f"{tool}|{title}|{':'.join(clean_cves)}"


def enrich_remediations(findings: List[Dict], model: str = "gemma4:e4b",
                        session_id=None, timeout=None, progress_cb=None,
                        pointwise=False) -> List[Dict]:
    """Rewrite the "remediation" and "remediation_actionable" keys on each
    finding dict using the LLM, grounded in that finding's own evidence.
    Returns the same list, mutated in place, so callers that already hold a
    reference (bg_worker.py's all_findings) see the change without needing to
    reassign anything.

    pointwise (VAPT scans): the recommendation as 3-4 "- " points and the
    developer steps as 3-5 numbered steps, one per line, asked for two
    findings per call. Off: the prose prompt, and the text stored as the model
    wrote it, exactly as before (PQC scans).

    Every other key -- severity, cve_list, control_id, title, evidence,
    dedup_key -- is read-only here and is never written to.

    Two things changed from a plain "batch through every finding" loop:

    1. Findings are grouped by _vuln_type_key() first, and only ONE finding
       per group (the LLM COST unit) is actually sent for enrichment; every
       other member of that group gets the same result copied onto it
       afterward. A large scan with the same handful of vulnerabilities
       repeated across many hosts collapses from hundreds of LLM calls to a
       few dozen, with no change to wording quality -- the text really is the
       same advice either way.
    2. The resulting batches run several AT ONCE instead of one after another
       -- see _MAX_PARALLEL_BATCHES.

    Neither optimization changes what gets asked or how it gets judged; a scan
    where every finding is a genuinely distinct vulnerability (no repeats)
    still pays for every one of them, exactly as before.
    """
    if not findings:
        return findings

    groups: Dict[str, List[Dict]] = {}
    order: List[str] = []
    for f in findings:
        key = _vuln_type_key(f)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    representatives = [groups[key][0] for key in order]
    for key in order:
        groups[key][0]["_group_size"] = len(groups[key])
    if len(representatives) < len(findings):
        print(f"[REMEDIATION LLM] {len(findings)} finding(s) collapsed to "
              f"{len(representatives)} unique vulnerability type(s) for enrichment "
              f"({len(findings) - len(representatives)} duplicate host instance(s) "
              f"will reuse the same text).", flush=True)

    size = _POINTWISE_BATCH_SIZE if pointwise else _BATCH_SIZE
    batches = [representatives[i:i + size] for i in range(0, len(representatives), size)]
    # Count what actually landed. A failed batch keeps its parser text, which is a
    # valid report -- but the auditor asked for AI-tailored text and got the canned
    # version, and nothing anywhere said so. The caller surfaces this.
    _results = []

    def _done(n):
        """Report completed batches. Never let a reporting failure stop the run."""
        if progress_cb:
            try:
                progress_cb(n, len(batches))
            except Exception:
                pass

    from src.core.llm_capacity import fair_share, model_slots, active_scans, scan_using_llm

    def _run_one(b):
        try:
            return bool(_enrich_batch(b, model, session_id=session_id, timeout=timeout,
                                      pointwise=pointwise))
        except Exception:
            return False                     # keeps its parser-generated text

    failed_batches = []
    with scan_using_llm(session_id or f"enrich-{id(findings)}"):
        if batches:
            print(f"[REMEDIATION LLM] {len(batches)} batch(es); up to {fair_share()} at once "
                  f"({model_slots()} model slot(s), {active_scans()} scan(s) using the model).",
                  flush=True)
        # In flight at any moment: this scan's fair share of the model's slots,
        # read again whenever a batch finishes -- so a scan grows into slots
        # another one releases and makes room when a new one starts.
        pending = list(batches)
        done_n = 0
        with ThreadPoolExecutor(max_workers=max(1, min(_MAX_PARALLEL_BATCHES, len(batches)))) as pool:
            inflight = {}
            while pending or inflight:
                while pending and len(inflight) < min(fair_share(), _MAX_PARALLEL_BATCHES):
                    b = pending.pop(0)
                    inflight[pool.submit(_run_one, b)] = b
                finished, _ = wait(list(inflight), return_when=FIRST_COMPLETED)
                for fut in finished:
                    b = inflight.pop(fut)
                    ok = fut.result()
                    _results.append(ok)
                    if not ok:
                        failed_batches.append(b)
                    done_n += 1
                    _done(done_n)

        # A batch that still failed (the model stopped responding, or its reply
        # could not be read) is asked again, alone, once the others are done --
        # up to _RETRY_ATTEMPTS times -- rather than leaving the canned text.
        for attempt in range(1, _RETRY_ATTEMPTS + 1):
            if not failed_batches:
                break
            print(f"[REMEDIATION LLM] Retrying {len(failed_batches)} batch(es), "
                  f"attempt {attempt} of {_RETRY_ATTEMPTS}.", flush=True)
            if _RETRY_DELAY_SEC > 0:
                time.sleep(_RETRY_DELAY_SEC)
            failed_batches = [b for b in failed_batches if not _run_one(b)]

    _failed = len(failed_batches)
    if _failed:
        print(f"[REMEDIATION LLM] {_failed}/{len(batches)} batch(es) failed -- those "
              f"finding(s) keep their parser-generated text.", flush=True)
    enrich_remediations.last_failed_batches = _failed
    enrich_remediations.last_total_batches = len(batches)

    # Copy each representative's (possibly still-original, if enrichment
    # failed for that batch) text onto every other member of its group.
    for key in order:
        members = groups[key]
        rep = members[0]
        rep.pop("_group_size", None)
        for dup in members[1:]:
            dup["remediation"] = rep.get("remediation", dup.get("remediation"))
            dup["remediation_actionable"] = rep.get("remediation_actionable", dup.get("remediation_actionable"))

    return findings
