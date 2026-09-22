# -*- coding: utf-8 -*-
"""Every option in the findings filter must be able to return something.

    pytest tests/test_findings_filters.py -v

WHY THIS EXISTS

The status filter offers "Unreviewed / Open Gaps". It fell through to the
generic branch at the end of the chain, which tests

    (f.status || "").toLowerCase().includes("open")

and no finding ever carries "Open" as its status. The audit writes
"Non-Compliant", "COMPLIANT" or "Informational"; "Open" is written to
display_status, a different field. Checked against the development database:
of 1,922 findings, the only status values present are Informational (1104),
Non-Compliant (777), COMPLIANT (36) and NON_COMPLIANT (5). The option returned
an empty list every single time it was chosen, and looked like "there are no
unreviewed gaps" rather than "this filter does not work".

The second half guards the run lock. applySessionFramework() re-renders the
scope panel through loadFrameworkControls(), which does not consult
window._scopeRunLocked -- so syncing the framework while a scan was executing
would blank and rebuild the scope behind the lock that exists to stop exactly
that.
"""
import io
import os
import re


APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "src", "api", "static", "app.js")
INDEX_HTML = os.path.join(os.path.dirname(APP_JS), "index.html")


def _app_js():
    return io.open(APP_JS, encoding="utf-8").read()


def _filter_chain():
    src = _app_js()
    start = src.index('if (valLower !== "all") {')
    return src[start:start + 2000]


# ── the dead option ──────────────────────────────────────────────────────────

def test_the_open_filter_has_a_branch_of_its_own():
    chain = _filter_chain()
    assert 'valLower.includes("open")' in chain, (
        '"Unreviewed / Open Gaps" has no branch, so it falls through to the '
        'substring test on status -- which no finding can ever match')


def test_the_open_filter_does_not_match_on_status_text():
    """status never contains "Open"; the field that does is display_status."""
    chain = _filter_chain()
    m = re.search(r'valLower\.includes\("open"\).*?\n(.*?)\n\s*\} else \{', chain, re.S)
    assert m, "the open branch could not be read"
    body = m.group(1)
    assert "human_verified" in body, (
        "an unreviewed gap is one nobody has acted on -- that is human_verified, "
        "not a string match on status")
    assert "isFindingCompliant" in body, "an open GAP must exclude passes"


def test_every_status_option_is_reachable():
    """Each option in the dropdown must hit a branch that can match."""
    html = io.open(INDEX_HTML, encoding="utf-8").read()
    block = html[html.index('id="status-filter"'):]
    block = block[:block.index("</select>")]
    values = re.findall(r'<option value="([^"]+)"', block)
    assert values, "no options found on the status filter"

    chain = _filter_chain()
    for v in values:
        low = v.lower()
        if low == "all":
            continue
        if "non" in low or "gap" in low:
            assert 'valLower.includes("non")' in chain, v
        elif "compliant" in low:
            assert 'valLower.includes("compliant")' in chain, v
        else:
            assert 'valLower.includes("%s")' % low in chain, (
                '"%s" has no branch of its own and will fall through to a '
                'substring match on status' % v)


# ── the run lock ─────────────────────────────────────────────────────────────

def test_the_framework_sync_stops_while_a_run_is_locked():
    src = _app_js()
    m = re.search(r"function applySessionFramework\(framework\) \{.*?\n\}",
                  src, re.S)
    assert m, "applySessionFramework not found"
    head = m.group(0)
    assert "_scopeRunLocked" in head, (
        "applySessionFramework does not check the run lock, and it calls "
        "loadFrameworkControls(), which blanks and rebuilds the scope panel")
    # The guard has to come before the re-render, not after it.
    assert head.index("_scopeRunLocked") < head.index("sel.value = match.value"), (
        "the run-lock guard sits after the select is already reassigned")


def test_load_framework_controls_is_still_the_thing_being_guarded():
    """If it ever learns the flag itself, this guard can be reconsidered."""
    src = _app_js()
    start = src.index("async function loadFrameworkControls()")
    body = src[start:start + 600]
    assert "_scopeRunLocked" not in body, (
        "loadFrameworkControls now checks the run lock itself -- the guard in "
        "applySessionFramework may no longer be needed")
