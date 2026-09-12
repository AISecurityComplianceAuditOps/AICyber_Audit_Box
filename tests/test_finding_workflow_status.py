# -*- coding: utf-8 -*-
"""Accept / Reject / Modify must not rewrite the verdict the audit reached.

    pytest tests/test_finding_workflow_status.py -v

WHY THIS EXISTS

The finding card carries three actions -- Accept, Modify, Reject -- and all
three arrive at PUT /audit/findings/{id} as `status`. Only the Modify dialog's
dropdown names a compliance verdict; Accept and Reject are workflow states.

final_result used to be derived as COMPLIANT for the literal string "COMPLIANT"
and NON_COMPLIANT for everything else. So clicking Accept on a passing control
rewrote its verdict to NON_COMPLIANT, and everything downstream reads
final_result before status:

  * the finding card  -- isComp is `backendFinalResult === "COMPLIANT"`
  * report_exporter   -- the programmatic DOCX and the PDF both branch on
                         `f.get("final_result") or f.get("status")`

so a control the auditor had just signed off was published to the customer as a
non-compliance, at whatever severity it happened to carry. The master-template
DOCX path disagreed with both of the others, because its _risk_level() reads
`status` and already treats "accepted" and "compliant" alike -- one report,
three code paths, two of them wrong about the same finding.

"Accepted" means acceptable in this product; report_exporter says so in the
report itself: "OK/ACCEPTED: This is normal and good practice ... need no
action." These tests pin that reading.

Reject is the other half. It says the finding was thrown out, not that the
control failed, so it must leave final_result alone -- that is what lets
Restore/Undo put the finding back as it was instead of guessing.
"""
import ast
import io
import os
import re

import pytest

from src.api.endpoints import audit as audit_ep
from src.core import finding_status


_APP_JS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "api", "static", "app.js",
)


def _app_js():
    with io.open(_APP_JS, encoding="utf-8") as fh:
        return fh.read()


def _top_level_function_source(name):
    """One function's source, sliced to the next top-level declaration.

    Brace matching is not an option here: app.js is mostly template literals
    full of CSS and `${...}` interpolation, so counting braces walks straight
    off the end. Every function in the file is declared in column 0, which is
    the boundary this uses instead.
    """
    src = _app_js()
    start = src.index("function %s(" % name)
    if start and src[start - 6:start] == "async ":
        start -= 6
    rest = src[start + 1:]
    ends = [m.start() for m in re.finditer(r"\n(?:async )?function [A-Za-z_$]", rest)]
    return rest[:ends[0]] if ends else rest


def _render_findings_list_source():
    return _top_level_function_source("renderFindingsList")


def _code_only(js):
    """Drop whole-line // comments, so the note left where the duplicate card
    renderer used to sit is not mistaken for the renderer coming back."""
    return "\n".join(l for l in js.split("\n") if not l.lstrip().startswith("//"))


# ── the verdict derivation itself ────────────────────────────────────────────

@pytest.mark.parametrize("status,previous,expected", [
    # The regression: signing off a passing control must leave it passing.
    ("Accepted", "COMPLIANT", "COMPLIANT"),
    # Accept is an override too -- the auditor is saying "this is acceptable".
    ("Accepted", "NON_COMPLIANT", "COMPLIANT"),
    ("accepted", None, "COMPLIANT"),
    # The Modify dialog's own dropdown values.
    ("Compliant", None, "COMPLIANT"),
    ("COMPLIANT", None, "COMPLIANT"),
    ("Non-Compliant", None, "NON_COMPLIANT"),
    ("Partially Compliant", None, "NON_COMPLIANT"),
    # Workflow-only statuses preserve whatever verdict was already recorded,
    # so Restore/Undo has something true to put back.
    ("Rejected", "COMPLIANT", "COMPLIANT"),
    ("Rejected", "NON_COMPLIANT", "NON_COMPLIANT"),
    ("Out Of Scope", "COMPLIANT", "COMPLIANT"),
    ("Dismissed", "NON_COMPLIANT", "NON_COMPLIANT"),
    # ... and fall back to NON_COMPLIANT only when there is nothing to preserve.
    ("Rejected", None, "NON_COMPLIANT"),
    ("Rejected", "", "NON_COMPLIANT"),
])
def test_derive_final_result(status, previous, expected):
    assert audit_ep._derive_final_result(status, previous) == expected


def test_accept_does_not_manufacture_a_non_compliance():
    """The one-line statement of the bug this file exists for."""
    assert audit_ep._derive_final_result("Accepted", "COMPLIANT") != "NON_COMPLIANT"


def test_unknown_status_is_treated_as_non_compliant():
    """An unrecognised status must never read as a pass -- fail closed."""
    for junk in ("", None, "   ", "Whatever", "In Review"):
        assert audit_ep._derive_final_result(junk, "COMPLIANT") == "NON_COMPLIANT"


# ── the browser copy of the same rule ────────────────────────────────────────

def _js_string_list(name):
    src = _app_js()
    m = re.search(re.escape(name) + r"\s*=\s*\[([^\]]*)\]", src)
    assert m, "%s not found in app.js" % name
    return [s.strip().strip('"').strip("'") for s in m.group(1).split(",") if s.strip()]


def _py_string_list(name):
    """Read the tuple out of src/core/finding_status.py, which owns it."""
    with io.open(finding_status.__file__.replace(".pyc", ".py"), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == name:
            return list(ast.literal_eval(node.value))
    raise AssertionError("%s not found in finding_status.py" % name)


@pytest.mark.parametrize("name", ["ACCEPTING_STATUSES", "WORKFLOW_ONLY_STATUSES"])
def test_js_and_python_status_lists_agree(name):
    """app.js moves the local copy of final_result so the card does not have to
    wait for a reload. If the two lists drift, the card and the database
    disagree about the same click."""
    assert _js_string_list("_" + name) == _py_string_list(name)


def test_workflow_update_keeps_the_local_final_result_in_step():
    fn = _top_level_function_source("updateFindingWorkflowStatus")
    assert "deriveFinalResult(status" in fn, (
        "updateFindingWorkflowStatus must move final_result too -- the card's "
        "isComp reads final_result, not status"
    )


def test_restore_does_not_hardcode_compliant():
    """Undoing a reject used to mark a real non-compliance as passing and wipe
    its severity to N/A."""
    fn = _top_level_function_source("restoreFindingCard")
    assert 'JSON.stringify({ status: "COMPLIANT" })' not in fn
    assert "restoredStatus" in fn


# ── the finding card ─────────────────────────────────────────────────────────

def test_only_one_vapt_branch_in_render_findings_list():
    """A second `if (isVapt)` was nested inside the first one's else, so its
    VAPT arm could never run. It held a stale copy of the card -- no CVE
    escaping, band-midpoint CVSS instead of the assessed score -- which made it
    a trap: a fix applied there would have looked right and changed nothing."""
    body = _code_only(_render_findings_list_source())
    assert body.count("if (isVapt)") == 1, (
        "renderFindingsList has %d `if (isVapt)` branches; the duplicate card "
        "renderer is back" % body.count("if (isVapt)")
    )


def test_exactly_two_card_renders_one_per_framework_family():
    body = _code_only(_render_findings_list_source())
    assert body.count("card.innerHTML = `") == 2, (
        "expected exactly two card templates (VAPT/PQC and ISO), found %d"
        % body.count("card.innerHTML = `")
    )


def test_edit_modal_classifies_pqc_the_same_way_the_card_does():
    """isPqcFinding() keys on quantum_status, which the API serialises as
    `f.quantum_status or ""` -- falsy in JS. The card classifies on the control
    id instead, so a PQC finding with no stored quantum_status rendered as a PQC
    card and then offered the ISO severity vocabulary in Modify."""
    fn = _top_level_function_source("openEditFindingModal")
    m = re.search(r"const isPqc = ([^;]+);", fn)
    assert m, "isPqc assignment not found in openEditFindingModal"
    assert "PQC" in m.group(1), (
        "openEditFindingModal must fall back to the control-id signal the card "
        "uses, not quantum_status alone -- got: %s" % m.group(1).strip()
    )


# ── the knowledge loop ───────────────────────────────────────────────────────

class _Feedback(object):
    """The shape AuditorFeedback rows have. It carries none of the columns
    filter_feedback_record() screens on (hallucination_check, confidence,
    human_verified), so every row of it reaches format_loop_hints()."""

    def __init__(self, status, comment=""):
        self.control_id = "8.17"
        self.corrected_status = status
        self.auditor_comments = comment
        self.finding = "The system clock is not synchronised with any time source."
        self.recommendation = ""


@pytest.mark.parametrize("status", [
    "Accepted",              # the one-click button on the card
    "Rejected",
    "Compliant",
    "Non-Compliant",
    "Partially Compliant",   # the Modify dropdown
    "Out Of Scope",
    "COMPLIANT",
    "NON_COMPLIANT",
])
def test_every_real_status_teaches_the_loop_something(status):
    """A status correction is knowledge on its own -- most auditors click and
    type nothing. The recogniser used to test against a tuple that contained
    none of "Accepted", "Partially Compliant" or "Out Of Scope", so those were
    dropped in silence."""
    from src.ai.knowledge_loop import format_loop_hints
    assert format_loop_hints([_Feedback(status)]).strip(), (
        "%r taught the knowledge loop nothing" % status
    )


@pytest.mark.parametrize("junk", ["", None, "   ", "In Review", "Whatever"])
def test_unrecognised_status_teaches_the_loop_nothing(junk):
    """The prior is injected verbatim into another auditor's prompt, so an
    unrecognised value must not become one."""
    from src.ai.knowledge_loop import format_loop_hints
    assert not format_loop_hints([_Feedback(junk)]).strip()


def test_accept_is_taught_as_compliant_not_as_its_raw_string():
    from src.ai.knowledge_loop import format_loop_hints
    hint = format_loop_hints([_Feedback("Accepted")])
    assert "recorded it as COMPLIANT" in hint
    assert "recorded it as ACCEPTED" not in hint


def test_prior_is_worded_as_a_prior_not_as_evidence():
    """Handing the model a verdict to copy is a different bug -- a finding
    asserted from no evidence at all."""
    from src.ai.knowledge_loop import format_loop_hints
    hint = format_loop_hints([_Feedback("Accepted")])
    assert "not" in hint and "as evidence" in hint
    assert "only agree if the evidence supports it" in hint


# ── the report the customer actually receives ────────────────────────────────

_PDF_FINDING = {
    "control_id": "8.17",
    "control_name": "8.17 Clock Synchronization",
    "control": "8.17 Clock Synchronization",
    "description": "NTP is enabled and the clock is synchronised.",
    "gap_description": "NTP is enabled and the clock is synchronised.",
    "recommendation": "No action required.",
    "evidence_snippet": "System clock synchronized: yes",
    "source_files": "121_NTP_Server_Clock_Sync.jpg",
    "severity": "P2 High",
}
_PDF_META = {"brand_firm": "Dhiware Technologies Pvt Ltd", "framework": "ISO 27001"}


def _pdf_text(final_result):
    """The visible text of the exported PDF, pulled out of its content streams.

    The PDF layout has no master template to fall back on, so unlike the DOCX it
    always takes the programmatic path -- the one that reads final_result before
    status. That is the path this regression lived on.
    """
    import re as _re
    import zlib
    import src.core.report_exporter as rx

    f = dict(_PDF_FINDING)
    f["status"] = "Accepted"
    f["final_result"] = final_result
    out = rx.export_pdf_report("workflow status regression", [f], ["8.17"],
                               "COMPLETED", metadata=_PDF_META)
    data = out.getvalue() if hasattr(out, "getvalue") else out
    words = []
    for m in _re.finditer(br"stream\r?\n(.*?)endstream", data, _re.S):
        chunk = m.group(1)
        try:
            chunk = zlib.decompress(chunk)
        except Exception:
            pass
        for t in _re.finditer(br"\((.*?)\)\s*Tj", chunk, _re.S):
            words.append(t.group(1).decode("latin-1", "ignore"))
    return " ".join(words)


def test_accepted_finding_is_published_as_acceptable_not_as_a_risk():
    """The whole point, measured on the artifact the customer receives.

    With final_result forced to NON_COMPLIANT the observation row read
    "8.17 Clock Synchronization - NTP is enabled and the clock is synchronised.
    High (0.0)" -- a passing control published as a High risk finding.
    """
    import re as _re
    text = _pdf_text(audit_ep._derive_final_result("Accepted", "COMPLIANT"))
    row = _re.search(r"8\.17 Clock Synchronization.{0,120}", text)
    assert row, "the observation row is missing from the PDF entirely"
    row = row.group(0)
    # fpdf splits words across text runs, so match without the internal space.
    assert "Accept able" in row or "Acceptable" in row, row
    assert "High" not in row, "an accepted control is still published as a risk: %s" % row


# -- the Modify dialog must offer only the fields the record actually has ------

def test_checklist_findings_do_not_get_a_policy_field():
    """Checklist (CUSTOMIZE) is pure document Q&A since 57af2e5: it resolves no
    controls and post_process judges it on evidence_ok alone. The card already
    suppresses the policy badge; the dialog behind it kept offering
    "Policy Present? -> Not Found (Document Missing)"."""
    fn = _top_level_function_source("openEditFindingModal")
    assert "_isQaFinding" in fn, "the dialog does not know about Checklist runs"
    assert "edit-policy-group" in fn


def test_policy_hiding_is_gated_on_the_customize_run_flag():
    """Rule 3 of CLAUDE.md: change one scope mode at a time. Control (EXCEL) and
    Selective (MANUAL) are judged on policy AND evidence, so the policy field has
    to keep showing for them."""
    fn = _top_level_function_source("openEditFindingModal")
    m = re.search(r"_isQaFinding\s*=\s*([^;]+);", fn)
    assert m, "_isQaFinding assignment not found"
    assert "_sessionIsCustomizeRun" in m.group(1), (
        "policy hiding must key on the customize-run flag, not on anything the "
        "other two scoping modes also set -- got: %s" % m.group(1).strip()
    )
    hide = re.search(r"_polGroup\.style\.display\s*=\s*([^;]+);", fn)
    assert hide, "_polGroup display assignment not found"
    assert "_isQaFinding" in hide.group(1), hide.group(1)


def test_checklist_keeps_the_evidence_field():
    """Evidence is the one dimension Checklist mode does judge on -- hiding it
    would remove the only thing the auditor can correct."""
    fn = _top_level_function_source("openEditFindingModal")
    hide = re.search(r"_polGroup\.style\.display\s*=\s*([^;]+);", fn)
    assert "edit-finding-evidence" not in hide.group(1)
    # the evidence select is still read back when the dialog is saved
    submit = _top_level_function_source("handleEditFindingSubmit")
    assert 'getElementById("edit-finding-evidence").value' in submit
