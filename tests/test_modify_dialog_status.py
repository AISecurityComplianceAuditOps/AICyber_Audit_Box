# -*- coding: utf-8 -*-
"""The Modify dialog must open on the verdict, and offer only what applies.

    pytest tests/test_modify_dialog_status.py -v

WHY THIS EXISTS

Two things, found together.

The serious one. The dialog chose its opening status from the status text alone,
and mapped "Accepted" to "Compliant" -- what Accept meant before acaffc4. Accept
now confirms whatever verdict the audit reached, so an accepted NON-COMPLIANT
finding opened in Modify pre-selected "Compliant". Saving the dialog for any
reason -- correcting the recommendation, say -- turned a confirmed gap into a
pass, set its severity to N/A and dropped it from the non-conformities. On an ISO
audit that is a real finding silently deleted from the customer's report.

The requested one. The dropdown offered Compliant, Partially Compliant,
Non-Compliant and Out Of Scope on every finding; it now offers Compliant and
Non-Compliant. A finding the auditor wants excluded is Rejected from the card,
which keeps it out of the report.

THE SAFEGUARD

Findings saved as Partially Compliant or Out Of Scope before this still exist. A
<select> whose value names no visible option goes blank, and saving it would send
an empty status and overwrite what the auditor recorded. So the finding's CURRENT
status is always kept selectable, even when it is no longer offered.
"""
import io
import json
import os
import re
import shutil
import subprocess

import pytest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, "src", "api", "static", "app.js")
INDEX_HTML = os.path.join(ROOT, "src", "api", "static", "index.html")

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node not installed")


def _src():
    return io.open(APP_JS, encoding="utf-8").read()


def _fn(name):
    m = re.search(r"\nfunction " + re.escape(name) + r"\(.*?\n\}", _src(), re.S)
    assert m, "%s not found" % name
    return m.group(0)


def _node(script):
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True,
                         encoding="utf-8", timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def _opening_status(**finding):
    return _node(_fn("modifyDialogStatus")
                 + "\nconsole.log(JSON.stringify(modifyDialogStatus(%s)));" % json.dumps(finding))


def _dialog_options():
    """The option values of the real edit-finding-status <select>."""
    html = io.open(INDEX_HTML, encoding="utf-8").read()
    block = html[html.index('id="edit-finding-status"'):]
    block = block[:block.index("</select>")]
    return re.findall(r'<option value="([^"]+)"', block)


def _offered(current):
    """Apply the rule to the real options; report which stay selectable."""
    const = re.search(r"\nconst _MODIFY_STATUSES = \[[^\]]*\];", _src()).group(0)
    script = const + _fn("_applyModifyStatusOptions") + """
const select = { options: %s.map(v => ({ value: v, hidden: false, disabled: false })) };
_applyModifyStatusOptions(select, %s);
console.log(JSON.stringify(select.options.filter(o => !o.hidden && !o.disabled).map(o => o.value)));
""" % (json.dumps(_dialog_options()), json.dumps(current))
    return _node(script)


# ── the serious one ──────────────────────────────────────────────────────────

def test_an_accepted_non_compliance_opens_as_non_compliant():
    """Opening on "Compliant" is what let an edit erase a confirmed gap."""
    assert _opening_status(status="Accepted", final_result="NON_COMPLIANT") == "Non-Compliant"


def test_an_accepted_pass_opens_as_compliant():
    assert _opening_status(status="Accepted", final_result="COMPLIANT") == "Compliant"


def test_an_accept_with_no_verdict_fails_closed():
    """Nothing to confirm, so it cannot be read as a pass."""
    assert _opening_status(status="Accepted") == "Non-Compliant"


@pytest.mark.parametrize("status,verdict,expected", [
    ("Non-Compliant", "NON_COMPLIANT", "Non-Compliant"),
    ("Compliant", "COMPLIANT", "Compliant"),
    ("Rejected", "NON_COMPLIANT", "Non-Compliant"),
    ("Non-Compliant", None, "Non-Compliant"),
    ("COMPLIANT", None, "Compliant"),
])
def test_the_opening_status_follows_the_verdict(status, verdict, expected):
    f = {"status": status}
    if verdict:
        f["final_result"] = verdict
    assert _opening_status(**f) == expected


def test_the_verdict_wins_over_the_status_text():
    """Status text says one thing, the recorded verdict another."""
    assert _opening_status(status="Compliant", final_result="NON_COMPLIANT") == "Non-Compliant"


# ── the requested one ────────────────────────────────────────────────────────

@pytest.mark.parametrize("current", ["Compliant", "Non-Compliant"])
def test_only_compliant_and_non_compliant_are_offered(current):
    assert sorted(_offered(current)) == ["Compliant", "Non-Compliant"]


def test_the_dialog_still_carries_the_options_for_old_findings():
    """They are hidden, not deleted -- the safeguard below needs them."""
    opts = _dialog_options()
    for v in ("Compliant", "Non-Compliant", "Partially Compliant", "Out Of Scope"):
        assert v in opts, "%s was removed from the dialog" % v


# ── the safeguard ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("legacy", ["Partially Compliant", "Out Of Scope"])
def test_an_old_finding_keeps_its_own_status_selectable(legacy):
    """Otherwise the dropdown goes blank and saving overwrites it."""
    assert _opening_status(status=legacy, final_result="NON_COMPLIANT") == legacy
    offered = _offered(legacy)
    assert legacy in offered, "%s would open on a blank dropdown" % legacy
    assert "Compliant" in offered and "Non-Compliant" in offered
    other = "Out Of Scope" if legacy == "Partially Compliant" else "Partially Compliant"
    assert other not in offered


def test_the_opening_status_is_always_an_offered_option():
    """Whatever a finding opens on must be selectable, or the value is lost."""
    for f in ({"status": "Accepted", "final_result": "NON_COMPLIANT"},
              {"status": "Rejected", "final_result": "NON_COMPLIANT"},
              {"status": "Out Of Scope"}, {"status": "Partially Compliant"},
              {"status": ""}, {"status": "Informational"}):
        opening = _opening_status(**f)
        assert opening in _offered(opening), (f, opening)
