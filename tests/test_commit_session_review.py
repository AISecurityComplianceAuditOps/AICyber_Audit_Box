# -*- coding: utf-8 -*-
"""Reviewing a control must count as reviewing it.

    pytest tests/test_commit_session_review.py -v

WHY THIS EXISTS

Clicking Save to Shakthi DB raised "Some controls have not been reviewed yet"
and named a control the auditor had just accepted.

The per-finding flags were right. PUT /audit/findings/{id} sets human_verified
and is_saved_to_shakthi on every auditor action, so after an Accept the finding
is recorded as reviewed. The commit endpoint computed `unreviewed` correctly
from those flags -- and then threw the answer away:

    unreviewed = [f for f in findings if not human_verified or not saved]
    if not unreviewed and report.status != "Reviewed & Finalized":
        unreviewed = findings          # <- every finding, unconditionally

report.status only becomes "Reviewed & Finalized" at the END of that same
function, so on the first commit of any session it never was. The warning was
therefore unavoidable: an auditor who had accepted every control was still told
none had been reviewed, and the only way past it was "Force Accept & Save All"
-- which writes FORCE_ACCEPT_UNREVIEWED_CONTROLS into the Admin Audit Log
against the auditor who had in fact reviewed everything.

The flags are the record of review. The report status is the result of
committing, not a precondition for it.

The second half is the compliance score the same function stores, which counted
"ACCEPTED" as a pass -- a fifth copy of the status vocabulary, and the same
mistake the finding card's counter made. Accepting a non-compliance raised the
session's score.
"""
import io
import os
import re

import pytest

from src.core.finding_status import derive_final_result


AUDIT_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "src", "api", "endpoints", "audit.py")


def _source():
    return io.open(AUDIT_PY, encoding="utf-8").read()


def _commit_fn():
    """The body of api_commit_session_findings."""
    src = _source()
    start = src.index("def api_commit_session_findings(")
    end = src.index("\n@router.", start)
    return src[start:end]


class _F(object):
    """A Finding, as this endpoint reads one."""

    def __init__(self, status, human_verified=True, saved=True, final_result=None,
                 severity="HIGH", control_id="VAPT-4"):
        self.status = status
        self.human_verified = human_verified
        self.is_saved_to_shakthi = saved
        self.final_result = final_result
        self.severity = severity
        self.control_id = control_id
        self.control_name = "Visual PoC"


def _unreviewed(findings):
    """The rule the endpoint applies, mirrored from its source."""
    return [f for f in findings
            if not bool(f.human_verified) or not bool(f.is_saved_to_shakthi)]


# ── the reported bug ─────────────────────────────────────────────────────────

def test_a_session_status_cannot_override_the_per_finding_flags():
    """The line that made the warning unavoidable is gone."""
    body = _commit_fn()
    assert not re.search(
        r"if not unreviewed and report\.status != .Reviewed & Finalized.:\s*\n\s*unreviewed = findings",
        body), (
        "the commit endpoint again replaces an empty unreviewed list with every "
        "finding whenever the report is not already finalized -- which it never "
        "is on a first commit, so the warning fires however much was reviewed")


def test_an_accepted_finding_is_not_unreviewed():
    """The exact case reported: one control, accepted, session not finalized."""
    accepted = _F("Accepted", human_verified=True, saved=True,
                  final_result="NON_COMPLIANT")
    assert _unreviewed([accepted]) == [], (
        "an accepted finding is still being reported as unreviewed")


def test_a_genuinely_untouched_finding_is_still_caught():
    """The warning must keep working -- it exists for a reason."""
    untouched = _F("Non-Compliant", human_verified=False, saved=False)
    reviewed = _F("Accepted", final_result="NON_COMPLIANT")
    assert _unreviewed([untouched, reviewed]) == [untouched]


def test_saved_but_not_verified_is_still_unreviewed():
    assert len(_unreviewed([_F("Non-Compliant", human_verified=False, saved=True)])) == 1


def test_verified_but_not_saved_is_still_unreviewed():
    assert len(_unreviewed([_F("Accepted", human_verified=True, saved=False)])) == 1


# ── the compliance score the same function stores ────────────────────────────

def _score(findings):
    """The scoring rule, mirrored from the endpoint's source."""
    return sum(1 for f in findings
               if (str(f.final_result or "").strip().upper()
                   or derive_final_result(f.status, None)) == "COMPLIANT")


def test_accepting_a_non_compliance_does_not_raise_the_score():
    """Accept confirms the verdict; it does not turn a gap into a pass."""
    findings = [_F("Accepted", final_result="NON_COMPLIANT"),
                _F("Accepted", final_result="COMPLIANT")]
    assert _score(findings) == 1, (
        "an accepted non-compliance is being counted toward the compliance score")


def test_the_score_no_longer_reads_accepted_as_a_pass():
    body = _commit_fn()
    assert '("COMPLIANT", "ACCEPTED", "PASS")' not in body, (
        "the compliance score still treats ACCEPTED as a pass")
    assert "f.final_result" in body, (
        "the compliance score no longer reads the recorded verdict")


def test_a_finding_with_no_verdict_falls_back_to_its_status():
    """Older rows predate final_result being written."""
    assert _score([_F("Compliant", final_result=None)]) == 1
    assert _score([_F("Non-Compliant", final_result=None)]) == 0
    # Nothing to confirm, so an accept cannot be read as a pass.
    assert _score([_F("Accepted", final_result=None)]) == 0
