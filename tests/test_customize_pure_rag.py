# -*- coding: utf-8 -*-
"""Customize scope is pure document Q&A -- and Excel/Manual scope is not.

Most tests here come in two halves: what Customize must now do, and the same call
in Excel mode proving it still does exactly what it did before. The whole risk in
this change is a shared code path (the scope payload builder, the control builder,
post_process) quietly changing shape for all three modes, so each one is pinned
from both sides.
"""
import pytest

from src.api.endpoints.controls import _build_scope_payload
from src.core.bg_worker import _build_controls_for_audit
from src.core.validator import finalize_rag_answer, post_process
from src.ai.audit_chains import (
    RAG_QA_PROMPT_TEMPLATE,
    EXCEL_SCOPING_JUDGE_PROMPT_TEMPLATE,
    get_rag_qa_chain,
    get_excel_scoping_chain,
)


def _rows():
    return [
        {"row_index": 1, "question": "Whether NTP is enabled and synchronized?",
         "requirement_question": "Whether NTP is enabled and synchronized?",
         "control_id": "8.17", "control_label": "8.17 Clock Synchronization",
         "expected_evidence": "NTP configuration", "files": ["121_NTP.jpg"],
         "raw_file_refs": ["121_NTP.jpg"], "severity": "MEDIUM"},
        {"row_index": 2, "question": "How is authentication implemented?",
         "requirement_question": "How is authentication implemented?",
         "control_id": "8.5", "control_label": "8.5 Secure Authentication",
         "expected_evidence": "Authentication remark", "files": ["Auth.txt"],
         "raw_file_refs": ["Auth.txt"], "severity": "HIGH"},
    ]


# -- Scope build -------------------------------------------------------------

def test_customize_scope_resolves_no_controls():
    """A Customize sheet puts questions in scope, not controls."""
    payload = _build_scope_payload(_rows(), rag_mode=True)

    assert payload["matched_sls"] == []          # nothing for the UI to tick
    assert payload["rag_mode"] is True
    assert payload["total_rows"] == 2
    assert payload["warning"] is None            # unmatched controls are not a fault here

    for item in payload["custom_evidence"]["excel_items"]:
        # Even a control the sheet named is dropped: leaving it on the row is
        # enough for the worker, the card and the export to start describing this
        # as an audit of that control.
        assert item["control_id"] == ""
        assert item["control_label"] == ""
        assert item["expected_evidence"] == ""
        assert item["rag_mode"] is True
        assert item["policy_required"] is False
        assert item["question"]                  # the question itself survives
        assert item["files"]                     # so does the document cited for it


def test_excel_scope_still_resolves_controls():
    """Regression: the shared builder is unchanged for Excel scoping."""
    payload = _build_scope_payload(_rows())

    assert len(payload["matched_sls"]) == 2      # both rows resolved as before
    assert "rag_mode" not in payload
    items = payload["custom_evidence"]["excel_items"]
    assert items[0]["control_id"] == "8.17"
    assert items[0]["expected_evidence"] == "NTP configuration"


# -- Control build -----------------------------------------------------------

def test_customize_builds_question_items_with_no_control_framing():
    scoped = _build_scope_payload(_rows(), rag_mode=True)
    controls = _build_controls_for_audit(
        custom_evidence=scoped["custom_evidence"], scoping_mode="CUSTOMIZE")

    assert len(controls) == 2
    first = controls[0]
    assert first["rag_mode"] is True
    assert first["customize_mode"] is True
    assert first["policy_required"] is False
    assert first["label"] == "Whether NTP is enabled and synchronized?"
    assert first["checklist_question"] == "Whether NTP is enabled and synchronized?"
    assert first["row_index"] == 1               # what locks retrieval to this row's file
    # None of the control scaffolding: no ISO recommendation boilerplate, no
    # expected-evidence text, no standard, and no control keywords steering
    # retrieval away from the question the auditor actually asked.
    assert first["recommendation"] == ""
    assert first["expected"] == ""
    assert first["standard"] == ""
    assert first["keywords"] == {}


def test_excel_control_build_is_untouched():
    """Regression: Excel rows still produce control-shaped items."""
    controls = _build_controls_for_audit(
        custom_evidence={"excel_items": _rows()}, scoping_mode="EXCEL")

    first = controls[0]
    assert not first.get("rag_mode")
    assert first["customize_mode"] is False
    assert first["policy_required"] is True
    assert first["control_id"] == "8.17 Clock Synchronization"
    assert first["standard"] == "ISO 27001"
    assert first["recommendation"].startswith("Establish, document, and implement")


# -- Verdict: the answer decides ---------------------------------------------

def _answer(text, **kw):
    finding = {
        "justification": text, "control_id": "Q1", "rag_mode": True,
        "control_label": "Whether NTP is enabled?", "status": "NON_COMPLIANT",
        "evidence_quote": "System clock synchronized: yes", "severity": "P3 Medium",
        # What the schema defaults leave behind when the prompt never asks for them.
        "policy_status": "NOT_FOUND", "policy_assessment": "NON_COMPLIANT",
        "policy_gap": "No documented policy was provided.", "policy_present": "No",
        "evidence_relevance": "IRRELEVANT",
    }
    finding.update(kw)
    return finalize_rag_answer(finding)


@pytest.mark.parametrize("text,expected", [
    ("Yes, NTP is enabled and synchronized on the host.", "COMPLIANT"),
    ("No, NTP is not enabled on this host.", "NON_COMPLIANT"),
    ("Not stated, the document does not address time synchronization.", "NON_COMPLIANT"),
])
def test_answer_decides_the_verdict(text, expected):
    assert _answer(text)["status"] == expected


def test_a_yes_answer_never_shows_a_red_badge():
    """The answer the auditor reads and the badge beside it cannot disagree.

    This is the specific failure the mode replaces: a COMPLIANT verdict whose
    justification opened "No, ... according to a documented policy" -- policy
    reasoning on a row that has no policy -- leaving a red cross beside a "No"
    on a control that had actually passed.
    """
    result = _answer("Yes, NTP is enabled and synchronized on 172.16.32.18.")
    assert result["status"] == "COMPLIANT"
    assert result["final_result"] == "COMPLIANT"
    assert result["description"].startswith("Yes,")
    assert result["severity"] == "N/A"


def test_unanswered_question_is_flagged_for_a_human():
    result = _answer("Not stated, the screenshot shows only disk usage.")
    assert result["requires_human_review"] is True
    assert result["review_note"]


def test_invented_quote_cannot_support_a_yes():
    result = _answer("Yes, NTP is enabled.", hallucination_check="NOT_GROUNDED")
    assert result["status"] == "NON_COMPLIANT"
    assert result["requires_human_review"] is True


def test_a_question_that_timed_out_keeps_its_own_status():
    """A timeout is not an answer, so no verdict is derived from one."""
    result = _answer("", status="NOT_EVALUATED", justification="")
    assert result["status"] == "NOT_EVALUATED"


def test_no_policy_dimension_survives_into_the_finding():
    result = _answer("No, NTP is not enabled.")
    for field in ("policy_status", "policy_assessment", "policy_present",
                  "policy_gap", "evidence_relevance", "evidence_status"):
        assert result[field] == "", field
    assert result["policy_required"] is False
    # bg_worker fills a blank recommendation with control boilerplate at save
    # time, so this one is never left blank.
    assert result["recommendation"]
    assert "policy" not in result["recommendation"].lower()


# -- post_process routing ----------------------------------------------------

_DOC = "Terminal: NTP enabled: yes. System clock synchronized: yes. Host 172.16.32.18."


def _draft(**kw):
    draft = {
        "status": "COMPLIANT", "severity": "N/A", "control_id": "Q1",
        "justification": "Yes, NTP is enabled and the clock is synchronized.",
        "evidence": [{"source": "121_NTP.jpg", "page": "1",
                      "excerpt": "System clock synchronized: yes"}],
        "policy_status": "NOT_FOUND", "policy_assessment": "NON_COMPLIANT",
        "evidence_relevance": "IRRELEVANT", "recommendation": "",
        "source_files": "121_NTP.jpg",
    }
    draft.update(kw)
    return draft


def test_post_process_skips_the_control_machinery_for_questions():
    out = post_process(_draft(rag_mode=True, customize_mode=True), _DOC)

    assert out["status"] == "COMPLIANT"
    # The dual policy+evidence rule would have failed this on the missing policy;
    # the requirement decomposition and the NIST rating never ran at all.
    assert out.get("requirements_total") is None
    assert not out.get("requirements_coverage_json")
    assert out["policy_status"] == ""
    # Grounding still ran -- that gate is not part of the control machinery.
    assert out["hallucination_check"] in ("GROUNDED", "GROUNDED_WITH_OCR_WARNING")


def test_post_process_still_applies_the_dual_rule_without_rag_mode():
    """Regression: an Excel row with no policy is still a gap."""
    out = post_process(_draft(control_id="8.17 Clock Synchronization"), _DOC)

    assert out["final_result"] == "NON_COMPLIANT"   # evidence alone is not enough
    assert out["policy_status"] == "NOT_FOUND"      # policy fields are kept, not cleared


# -- Prompt selection --------------------------------------------------------

def test_customize_prompt_carries_no_control_or_policy_framing():
    prompt = RAG_QA_PROMPT_TEMPLATE.format(
        locked_filenames="121_NTP.jpg",
        checklist_question="Whether NTP is enabled?",
        condensed_context="NTP enabled: yes",
    )
    low = prompt.lower()
    for phrase in ("lead auditor", "control objective", "annex", "policy_status",
                   "policy_assessment", "evidence_relevance", "false_positive"):
        assert phrase not in low, phrase
    assert "yes," in low and "not stated," in low     # the three openers
    assert "121_NTP.jpg" in prompt


def test_the_two_modes_use_two_different_prompts():
    assert get_rag_qa_chain("m").prompt_template is RAG_QA_PROMPT_TEMPLATE
    assert get_excel_scoping_chain("m").prompt_template is EXCEL_SCOPING_JUDGE_PROMPT_TEMPLATE
    # Excel keeps every rule it had.
    assert "EXCEL SCOPING MODE" in EXCEL_SCOPING_JUDGE_PROMPT_TEMPLATE
    assert "POLICY_STATUS" in EXCEL_SCOPING_JUDGE_PROMPT_TEMPLATE


# -- Impact ------------------------------------------------------------------

def test_an_answered_question_has_no_impact_to_report():
    """"Yes" means nothing went wrong, so there is no consequence to describe."""
    result = _answer("Yes, NTP is enabled and synchronized.",
                     business_impact="Some impact the model wrote anyway.")
    assert result["business_impact"] == ""
    assert result["recommendation"] == "No action required."


def test_a_failed_question_always_carries_an_impact_and_a_recommendation():
    """Both cells are filled, because a blank one tells the reader nothing."""
    result = _answer("No, the retry limit is 10 attempts.", business_impact="")
    assert result["business_impact"]
    assert result["recommendation"]
    # And no control vocabulary in either.
    for field in ("business_impact", "recommendation"):
        assert "control" not in result[field].lower(), field


def test_nil_placeholders_are_not_treated_as_an_impact():
    """The schema default for an omitted field is boilerplate, not content."""
    for placeholder in ("NIL", "N/A", "None", "not applicable"):
        result = _answer("No, it is disabled.", business_impact=placeholder)
        assert result["business_impact"].upper() not in ("NIL", "N/A", "NONE", "NOT APPLICABLE")


def test_the_prompt_asks_for_the_impact_in_plain_terms():
    assert "<business_impact>" in RAG_QA_PROMPT_TEMPLATE
    _block = RAG_QA_PROMPT_TEMPLATE.split("<business_impact>")[1].split("</business_impact>")[0]
    assert "clause" in _block.lower() and "do not cite" in _block.lower()
