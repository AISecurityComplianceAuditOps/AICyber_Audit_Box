# -*- coding: utf-8 -*-
"""The framework the auditor chose must be the framework that runs and prints.

    pytest tests/test_framework_routing.py -v

WHY THIS EXISTS

Two symptoms were reported from a customer installation:

  * a new session created as VAPT showed a different framework in the sidebar
  * an ISO 27001 audit sometimes exported as a VAPT report

They are one root cause. The sidebar <select> and the session's stored
framework were independent values, and nothing reconciled them:

  * nothing in app.js ever ASSIGNED framework-select, so it changed only when
    the auditor clicked it -- switching sessions left it showing the previous
    session's framework
  * /audit/start sends that sidebar value and the backend writes it OVER the
    session's stored framework, so running an audit from a stale sidebar
    silently reframes the session
  * the exporters then decided VAPT-vs-ISO with "framework says VAPT *or* any
    finding's control_id contains VAPT/PQC", so one stray control id turned a
    whole ISO audit into a VAPT report

The last one is measurable rather than theoretical. In the development database
five audit_reports rows with framework='ISO 27001' hold 1,497 findings whose
control_id starts with VAPT-, and every one of those sessions exported as a
VAPT report while its title, its sidebar and its framework column all said ISO.

An ISO checklist with a row labelled "VAPT-1", or a Checklist-mode question
mentioning PQC, is enough to trigger it on a customer machine.
"""
import io
import json
import os
import re
import shutil
import subprocess

import pytest

from src.api.endpoints.audit import _session_is_technical


_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(_ROOT, "src", "api", "static", "app.js")
AUDIT_PY = os.path.join(_ROOT, "src", "api", "endpoints", "audit.py")


def _app_js():
    return io.open(APP_JS, encoding="utf-8").read()


def _family_fn():
    """_frameworkFamily lifted out of app.js, for running under node."""
    m = re.search(r"function _frameworkFamily\(value\) \{.*?\n\}", _app_js(), re.S)
    assert m, "_frameworkFamily not found in app.js"
    return m.group(0)


def _node(script):
    out = subprocess.run(["node", "-e", script], capture_output=True,
                         text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return out.stdout.split()


# ───────────────────────────── the export dispatch ─────────────────────────

def test_a_recorded_framework_decides_the_report_type():
    assert _session_is_technical("VAPT Framework Controls", []) is True
    assert _session_is_technical("PQC Framework Controls", []) is True
    assert _session_is_technical("ISO 27001", []) is False


def test_stray_vapt_control_ids_cannot_turn_an_iso_audit_into_a_vapt_report():
    """The reported bug, in the exact shape the database holds it."""
    iso_with_vapt_ids = ["VAPT-3", "VAPT-5", "VAPT-12", "5.1", "8.17"]
    assert _session_is_technical("ISO 27001", iso_with_vapt_ids) is False, (
        "an ISO session still exports as VAPT because of its control ids")


def test_a_pqc_control_id_cannot_either():
    assert _session_is_technical("ISO 27001", ["PQC-1"]) is False


def test_control_ids_still_decide_when_no_framework_was_ever_recorded():
    """The fallback is kept -- it just may not override a recorded framework."""
    assert _session_is_technical("", ["VAPT-3"]) is True
    assert _session_is_technical(None, ["PQC-1"]) is True
    assert _session_is_technical("", ["5.1", "8.17"]) is False
    assert _session_is_technical("   ", ["VAPT-1"]) is True


def test_the_fallback_tolerates_none_control_ids():
    """db_findings routinely carry a null control_id or category."""
    assert _session_is_technical("", [None, "", "VAPT-1"]) is True
    assert _session_is_technical("", [None, ""]) is False


def test_both_exporters_share_one_rule():
    """The DOCX and PDF endpoints derived this separately and drifted apart.

    One report, two formats: if they disagree, the customer gets a VAPT PDF and
    an ISO DOCX for the same audit.
    """
    src = io.open(AUDIT_PY, encoding="utf-8").read()
    assert src.count("is_vapt = _session_is_technical(") == 2, (
        "an export path is deciding VAPT-vs-ISO on its own again")
    assert not re.search(r'is_vapt = \(\s*\n\s*"VAPT" in', src), (
        "the inline or-any-control-id rule is back")


# ─────────────────────────── the sidebar / session sync ────────────────────

def test_every_session_activation_syncs_the_sidebar():
    """Each path that makes a session active must reconcile the framework.

    Pinned per call site rather than in aggregate, because the bug was a path
    that simply forgot -- and the next new path is the next place to forget.
    """
    src = _app_js()
    for marker, why in [
        ("function switchActiveAuditSession(sessionId, framework) {",
         "switching from the Recent Sessions list"),
        ("switchActiveAuditSession(sess.session_id, sess.framework)",
         "the Recent Sessions click passes the session's framework"),
        ("applySessionFramework(framework);",
         "the session just created from the modal"),
        ("syncFrameworkFromSession(lastSid);",
         "the session restored from localStorage on load"),
        ("applySessionFramework(recent.framework);",
         "the most-recent-session restore"),
    ]:
        assert marker in src, "no framework sync on %s" % why


def test_the_sidebar_is_never_left_as_the_only_source_of_truth():
    """framework-select must be assignable, which it never was before."""
    src = _app_js()
    assert "sel.value = match.value;" in src, (
        "applySessionFramework no longer assigns the sidebar select")
    assert "onFrameworkChangeSuggestMode();" in src, (
        "the mode gating is not re-run after a scripted framework change -- the "
        "browser fires no change event for an assignment")


# ── the vocabulary mismatch that makes an exact-string match useless ───────

# stored framework -> the sidebar <option value> it has to select
_FAMILY_CASES = [
    ("VAPT Framework Controls", "VAPT"),
    ("PQC Framework Controls", "PQC"),
    ("SOC 2 Framework Controls", "SOC2"),
    ("X-BOM / SBOM Framework Controls", "XBOM"),
    ("ISO 22301 BCMS", "BCMS"),
    ("ISO 27001", "ISO 27001"),
    ("SOC 2", "SOC2"),
    ("DPDP", "DPDP"),
    ("GDPR", "DPDP"),
]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_stored_frameworks_map_onto_the_sidebar_options():
    """The DB stores 'VAPT Framework Controls'; the sidebar option is 'VAPT'.

    An exact-string match would fail on precisely the sessions this fixes, so
    the mapping is on framework family. Executed rather than pattern-matched --
    the ordering inside it is load-bearing ('ISO 22301 BCMS' contains both ISO
    and BCMS, and must resolve to BCMS).
    """
    checks = ";".join(
        "console.log(_frameworkFamily(%s) === _frameworkFamily(%s))"
        % (json.dumps(stored), json.dumps(option))
        for stored, option in _FAMILY_CASES)
    results = _node(_family_fn() + ";" + checks)
    assert results == ["true"] * len(_FAMILY_CASES), dict(
        zip([c[0] for c in _FAMILY_CASES], results))


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_vapt_and_iso_do_not_collapse_into_the_same_family():
    """The whole point: these two must stay distinguishable."""
    checks = ";".join([
        'console.log(_frameworkFamily("VAPT Framework Controls") !== _frameworkFamily("ISO 27001"))',
        'console.log(_frameworkFamily("PQC Framework Controls") !== _frameworkFamily("VAPT"))',
    ])
    assert _node(_family_fn() + ";" + checks) == ["true", "true"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_an_unrelated_framework_maps_to_nothing_rather_than_guessing():
    """No family means the sidebar is left alone.

    Assigning a value no <option> carries silently blanks a <select>, which is
    worse than showing a stale one.
    """
    checks = ";".join([
        'console.log(_frameworkFamily("PCI DSS") === "")',
        'console.log(_frameworkFamily("") === "")',
        'console.log(_frameworkFamily(null) === "")',
    ])
    assert _node(_family_fn() + ";" + checks) == ["true", "true", "true"]
