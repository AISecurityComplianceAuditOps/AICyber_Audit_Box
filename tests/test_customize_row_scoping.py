# -*- coding: utf-8 -*-
"""Customize rows are answered from the document they cite, and nothing else.

The sibling of test_excel_row_level_scoping.py, for the mode that has no controls.
Same harness -- the graph is mocked, so what is under test is the worker's file
scoping and the state it hands the graph, not the LLM.

Stack-gated for the same reason as its sibling (see tests/conftest.py): this walks
the real retrieval warm-up and takes tens of seconds rather than milliseconds.
"""
import unittest.mock as mock

import pytest

from src.core.bg_worker import _build_controls_for_audit, generate_ollama_findings


CUSTOM_EVIDENCE = {
    "excel_items": [
        {
            "row_index": 1,
            "question": "Whether NTP is enabled and synchronized?",
            "requirement_question": "Whether NTP is enabled and synchronized?",
            "control_id": "", "control_label": "",
            "files": ["121_NTP.jpg"], "raw_file_refs": ["121_NTP.jpg"],
            "customize_mode": True, "rag_mode": True, "policy_required": False,
        },
        {
            # No document named on the row.
            "row_index": 2,
            "question": "Whether log archival is done?",
            "requirement_question": "Whether log archival is done?",
            "control_id": "", "control_label": "",
            "files": [], "raw_file_refs": [],
            "customize_mode": True, "rag_mode": True, "policy_required": False,
        },
    ]
}

FILES = ["121_NTP.jpg", "Unrelated_Server_Log.log"]
REGISTRY = {
    "121_NTP.jpg": "NTP enabled: yes. System clock synchronized: yes.",
    "Unrelated_Server_Log.log": "Server started successfully. Log archived daily.",
}


def _run():
    """Runs a two-question Customize scan with the graph mocked out."""
    captured = {}

    with mock.patch("src.core.bg_worker._resolve_llm_model", return_value="gemma:2b"), \
         mock.patch("src.core.bg_worker.save_document_chunks"), \
         mock.patch("src.core.resource_guard.check_memory_pressure", return_value={"status": "OK"}), \
         mock.patch("src.core.bg_worker.audit_graph") as mock_graph:

        def capture_invoke(state_input, config=None):
            captured[state_input["control_id"]] = dict(state_input)
            return {
                "final_finding": {
                    "control_id": state_input["control_id"],
                    "control_label": state_input["control_label"],
                    "status": "COMPLIANT",
                    "justification": "Yes, NTP is enabled and synchronized.",
                    "recommendation": "No action required.",
                },
                "retrieved_context": "NTP enabled: yes",
            }

        mock_graph.invoke.side_effect = capture_invoke
        _resolved, _gaps, all_results, _paused = generate_ollama_findings(
            context="ctx", file_names_list=FILES, selected_sls=None,
            model_choice="gemma:2b", custom_evidence=CUSTOM_EVIDENCE,
            file_registry=REGISTRY, scoping_mode="CUSTOMIZE",
        )
    return captured, all_results


@pytest.mark.needs_stack
def test_a_question_is_answered_only_from_the_document_it_cites():
    captured, _ = _run()

    assert "Q1" in captured
    state = captured["Q1"]
    # The cited file, and only it -- never the unrelated log that happens to
    # contain the word "archived".
    assert state["file_names_list"] == ["121_NTP.jpg"]
    assert state["locked_filenames"] == ["121_NTP.jpg"]
    assert "Unrelated_Server_Log.log" not in state["file_names_list"]

    # And it reaches the graph as a question, not as a control.
    assert state["rag_mode"] is True
    assert state["checklist_question"] == "Whether NTP is enabled and synchronized?"
    assert state["expected_evidence"] == ""
    assert state["prompt_hint"] == ""
    assert state["keywords"] == {}


@pytest.mark.needs_stack
def test_a_question_with_no_document_is_never_answered_from_another_one():
    """The row is reported unanswered rather than searching the whole session.

    Without the Customize guard this fell through the Tier 2/3/4 cascade to
    "no filename/keyword match -- fall back to all uploaded files", so a question
    the auditor cited nothing for would have been answered out of a document they
    never pointed at.
    """
    captured, results = _run()

    assert "Q2" not in captured          # no retrieval, no LLM call at all

    q2 = next(r for r in results if r["control_id"] == "Q2")
    assert q2["status"] == "NON_COMPLIANT"
    assert "No document was cited" in q2["final_reason"]
    # No control language on the way out, and no policy deficiency reported
    # against a requirement this mode never had.
    assert q2["policy_status"] == ""
    assert q2["rag_mode"] is True
    assert "checklist row" in q2["recommendation"] or "checklist" in q2["recommendation"]


@pytest.mark.needs_stack
def test_the_run_still_produces_one_finding_per_question():
    controls = _build_controls_for_audit(
        custom_evidence=CUSTOM_EVIDENCE, scoping_mode="CUSTOMIZE")
    _captured, results = _run()

    assert len(controls) == 2
    assert sorted(r["control_id"] for r in results) == ["Q1", "Q2"]
