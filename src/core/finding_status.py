# -*- coding: utf-8 -*-
"""One vocabulary for the statuses a finding can be moved to.

The finding card offers Accept / Modify / Reject and the Modify dialog offers a
four-value Compliance Status dropdown. All of them arrive at
PUT /audit/findings/{id} as a single `status` string, and three separate places
then have to decide what that string means:

  * src/api/endpoints/audit.py  -- derives final_result, which the card's isComp
    and two of report_exporter's three layouts read in preference to status
  * src/ai/knowledge_loop.py    -- turns an auditor's correction into a prior for
    the next audit of the same control
  * src/api/static/app.js       -- moves its local copy of final_result so the
    card does not render a stale verdict until the next reload

Each of them used to carry its own list, and they disagreed. audit.py accepted
only the literal "COMPLIANT", so Accept on a passing control rewrote the verdict
to NON_COMPLIANT and published a false finding. knowledge_loop.py recognised
"COMPLIANT", "NON_COMPLIANT", "PARTIAL_COMPLIANT" and "FALSE_POSITIVE" -- none of
which is what the buttons send -- so a one-click Accept, the commonest auditor
action there is, taught the loop nothing at all.

The app.js copy is checked against this one by
tests/test_finding_workflow_status.py.
"""

# Statuses that say the control is satisfied and needs no action. The report
# says as much in its own words: "OK/ACCEPTED: This is normal and good practice.
# It is as per the guidelines / best practices. The observations categorized as
# 'ACCEPTED' need no action."
ACCEPTING_STATUSES = ("COMPLIANT", "ACCEPTED", "PASS", "PASSED", "SATISFIED")

# Statuses that describe what happened to the finding, not to the control. A
# rejected finding was thrown out; that says nothing about whether the control
# was met, so these must not overwrite a verdict.
WORKFLOW_ONLY_STATUSES = ("REJECTED", "DISMISSED", "FALSE_POSITIVE", "OUT_OF_SCOPE", "EXCLUDED")

# Statuses that assert a real shortfall.
FAILING_STATUSES = (
    "NON_COMPLIANT", "NONCOMPLIANT", "FAIL", "FAILED", "GAP",
    "PARTIAL_COMPLIANT", "PARTIALLY_COMPLIANT", "PARTIAL",
)


def normalise_status(status):
    """Upper-case, with hyphens and spaces folded to underscores."""
    return str(status or "").strip().upper().replace("-", "_").replace(" ", "_")


def derive_final_result(status, current_final_result=None):
    """Map an incoming UI status onto the COMPLIANT / NON_COMPLIANT verdict.

    Returns the exact values validator.py uses, so the database stays consistent
    with what the auditor chose. A workflow-only status leaves the recorded
    verdict alone -- those findings are filtered out of the report by status
    anyway, and preserving the verdict is what lets Restore/Undo put the finding
    back as it was instead of guessing.

    Anything unrecognised fails closed to NON_COMPLIANT: an unknown string must
    never be read as a pass.
    """
    normalised = normalise_status(status)
    if normalised in ACCEPTING_STATUSES:
        return "COMPLIANT"
    if normalised in WORKFLOW_ONLY_STATUSES:
        return str(current_final_result or "").strip().upper() or "NON_COMPLIANT"
    return "NON_COMPLIANT"


def is_recognised_status(status):
    """True when the string is one the UI can actually produce.

    knowledge_loop.py uses this to tell a real auditor correction apart from a
    junk or legacy value before it writes a prior into another audit's prompt.
    """
    normalised = normalise_status(status)
    return (normalised in ACCEPTING_STATUSES
            or normalised in WORKFLOW_ONLY_STATUSES
            or normalised in FAILING_STATUSES)
