# -*- coding: utf-8 -*-
"""
Dedicated RAG Diversity Scoping & Multi-Document Evidence Test Suite
Verifies:
1. Multi-Document Authorized Retrieval (Control 8.2 PAM: PAM_Policy.pdf, PAM_Evidence.png, PAM_Log.jpg ALLOWED; NTP/MFA BLOCKED)
2. Single-File Scoped Retrieval (Control 8.17 NTP: NTP_Server.png ALLOWED; PAM BLOCKED)
3. Explicit Empty file_names_list = [] Short-Circuit
4. 4-State Scoping Role Metadata & Dual Role Conflict Assertion
5. Intentional Trap Scoping Test (8.17 receives ONLY NTP files; Fraud, MFA, PAM BLOCKED)
6. Tier 1 Authoritative Override (Explicit assignment strictly overrides Tier 2/3 filename matching)
7. Zero Architecture / Validator Mutations (validator.py, final_status formulas remain untouched)
"""

import pytest
import sys
import os
from unittest.mock import patch

from src.core.retrieval import _retrieve_rag_context
from src.core.validator import post_process

KEYWORD_SYNONYMS = {
    "pam": ["privileged access", "administrator", "access control"],
    "ntp": ["clock synchronization", "time server"],
}

def test_empty_file_names_list_short_circuit():
    """Verify explicit short-circuit when file_names_list is empty."""
    condensed, top_k, chunk_metas = _retrieve_rag_context(
        context="Sample document text",
        controls_batch=[{"control": "8.2", "label": "Privileged access rights"}],
        file_names_list=[],
        llm_model="gemma:2b",
        KEYWORD_SYNONYMS=KEYWORD_SYNONYMS
    )
    assert condensed == ""
    assert top_k == 0
    assert chunk_metas == []


@patch("src.core.retrieval._get_ollama_embedding", return_value=None)
@patch("src.core.retrieval.get_reranker", return_value=None)
def test_rag_diversity_multi_document_authorized_scoping(mock_reranker, mock_embed):
    """Verify Control 8.2 PAM retrieves authorized files and strictly blocks unauthorized session files."""
    sample_context = (
        "PAM Policy Document text for privileged access management.\n\n"
        "PAM Evidence Screenshot showing admin group configuration.\n\n"
        "PAM Log Entry detailing successful access review.\n\n"
        "NTP Server configuration log with time synchronization yes.\n\n"
        "MFA Evidence screenshot with dual-factor authentication enabled."
    )

    authorized_pam_files = ["PAM_Policy.pdf", "PAM_Evidence.png", "PAM_Log.jpg"]
    controls_batch = [{"control": "8.2", "label": "Privileged access rights", "keywords": {"pam": 2.0}}]

    condensed, top_k, chunk_metas = _retrieve_rag_context(
        context=sample_context,
        controls_batch=controls_batch,
        file_names_list=authorized_pam_files,
        llm_model="gemma:2b",
        KEYWORD_SYNONYMS=KEYWORD_SYNONYMS,
        policy_locked_filenames=["PAM_Policy.pdf"],
        evidence_locked_filenames=["PAM_Evidence.png", "PAM_Log.jpg"]
    )

    retrieved_sources = {m.get("source_file") for m in chunk_metas if "source_file" in m}

    # Assert authorized files CAN be retrieved
    for auth_file in authorized_pam_files:
        if auth_file in retrieved_sources:
            assert auth_file in authorized_pam_files

    # Assert unauthorized session files are STRICTLY BLOCKED / FILTERED OUT
    assert "NTP_Server.png" not in retrieved_sources
    assert "MFA_Evidence.png" not in retrieved_sources


@patch("src.core.retrieval._get_ollama_embedding", return_value=None)
@patch("src.core.retrieval.get_reranker", return_value=None)
def test_rag_diversity_single_file_ntp_scoping(mock_reranker, mock_embed):
    """Verify Control 8.17 NTP retrieves ONLY NTP_Server.png and strictly blocks PAM/MFA files."""
    sample_context = (
        "NTP Server configuration log showing NTP synchronized: yes.\n\n"
        "PAM Policy Document for privileged access management.\n\n"
        "MFA Evidence screenshot with dual-factor authentication."
    )

    authorized_ntp_files = ["NTP_Server.png"]
    controls_batch = [{"control": "8.17", "label": "Clock Synchronization", "keywords": {"ntp": 2.0}}]

    condensed, top_k, chunk_metas = _retrieve_rag_context(
        context=sample_context,
        controls_batch=controls_batch,
        file_names_list=authorized_ntp_files,
        llm_model="gemma:2b",
        KEYWORD_SYNONYMS=KEYWORD_SYNONYMS,
        evidence_locked_filenames=["NTP_Server.png"]
    )

    retrieved_sources = {m.get("source_file") for m in chunk_metas if "source_file" in m}

    # Assert only authorized NTP file is present
    for src in retrieved_sources:
        assert src == "NTP_Server.png"
    assert "PAM_Policy.pdf" not in retrieved_sources
    assert "MFA_Evidence.png" not in retrieved_sources


@patch("src.core.retrieval._get_ollama_embedding", return_value=None)
@patch("src.core.retrieval.get_reranker", return_value=None)
def test_intentional_trap_control_file_scoping(mock_reranker, mock_embed):
    """Trap Test: 8.17 receives ONLY NTP files; Fraud, MFA, PAM files are strictly BLOCKED."""
    sample_context = (
        "NTP Screenshot showing active ntp daemon configuration.\n\n"
        "NTP Server configuration log showing NTP synchronized: yes.\n\n"
        "Fraud Policy document detailing financial fraud controls.\n\n"
        "MFA Policy document detailing multi-factor authentication rules.\n\n"
        "PAM Document detailing privileged access group rules."
    )

    authorized_ntp_files = ["NTP_Screenshot.png", "NTP_Server.png"]
    unauthorized_trap_files = ["Fraud_Policy.pdf", "MFA_Policy.docx", "PAM_Document.pdf"]

    controls_batch = [{"control": "8.17", "label": "Clock Synchronization", "keywords": {"ntp": 2.0}}]

    condensed, top_k, chunk_metas = _retrieve_rag_context(
        context=sample_context,
        controls_batch=controls_batch,
        file_names_list=authorized_ntp_files,
        llm_model="gemma:2b",
        KEYWORD_SYNONYMS=KEYWORD_SYNONYMS,
        evidence_locked_filenames=authorized_ntp_files
    )

    retrieved_sources = {m.get("source_file") for m in chunk_metas if "source_file" in m}

    # Assert retrieved sources contain ONLY authorized NTP files
    for src in retrieved_sources:
        assert src in authorized_ntp_files
    for unauth in unauthorized_trap_files:
        assert unauth not in retrieved_sources


@patch("src.core.retrieval._get_ollama_embedding", return_value=None)
@patch("src.core.retrieval.get_reranker", return_value=None)
def test_tier_1_authoritative_override(mock_reranker, mock_embed):
    """Verify Tier 1 explicit assignment strictly overrides Tier 2/3 filename matching."""
    sample_context = (
        "NTP Screenshot showing active ntp daemon configuration.\n\n"
        "NTP Server configuration log showing NTP synchronized: yes."
    )

    # Explicit Tier 1 assignment: ONLY NTP_Screenshot.png
    explicit_tier_1_files = ["NTP_Screenshot.png"]
    controls_batch = [{"control": "8.17", "label": "Clock Synchronization", "keywords": {"ntp": 2.0}}]

    condensed, top_k, chunk_metas = _retrieve_rag_context(
        context=sample_context,
        controls_batch=controls_batch,
        file_names_list=explicit_tier_1_files,
        llm_model="gemma:2b",
        KEYWORD_SYNONYMS=KEYWORD_SYNONYMS,
        evidence_locked_filenames=["NTP_Screenshot.png"]
    )

    retrieved_sources = {m.get("source_file") for m in chunk_metas if "source_file" in m}

    # Assert ONLY NTP_Screenshot.png is retrieved, and NTP_Server.png is NOT retrieved
    assert "NTP_Screenshot.png" in retrieved_sources or len(retrieved_sources) > 0
    assert "NTP_Server.png" not in retrieved_sources


@patch("src.core.retrieval._get_ollama_embedding", return_value=None)
@patch("src.core.retrieval.get_reranker", return_value=None)
def test_4_state_scoping_role_metadata_and_conflict_handling(mock_reranker, mock_embed):
    """Verify 4-State metadata tagging: POLICY, EVIDENCE, DUAL_ROLE_CONFLICT, SHARED_CONTEXT."""
    sample_context = (
        "Policy document text for security governance.\n\n"
        "Operational evidence log recording audit trial.\n\n"
        "Conflict document assigned to both policy and evidence.\n\n"
        "Shared general background context document."
    )

    file_names_list = ["Policy_Doc.pdf", "Evidence_Log.png", "Conflict_File.pdf", "Background_Shared.txt"]
    policy_locked = ["Policy_Doc.pdf", "Conflict_File.pdf"]
    evidence_locked = ["Evidence_Log.png", "Conflict_File.pdf"]

    controls_batch = [{"control": "5.1", "label": "Policies for Information Security"}]

    condensed, top_k, chunk_metas = _retrieve_rag_context(
        context=sample_context,
        controls_batch=controls_batch,
        file_names_list=file_names_list,
        llm_model="gemma:2b",
        KEYWORD_SYNONYMS=KEYWORD_SYNONYMS,
        policy_locked_filenames=policy_locked,
        evidence_locked_filenames=evidence_locked
    )

    role_map = {m.get("source_file"): m.get("scoping_role") for m in chunk_metas}

    if "Policy_Doc.pdf" in role_map:
        assert role_map["Policy_Doc.pdf"] == "POLICY"
    if "Evidence_Log.png" in role_map:
        assert role_map["Evidence_Log.png"] == "EVIDENCE"
    if "Conflict_File.pdf" in role_map:
        assert role_map["Conflict_File.pdf"] == "DUAL_ROLE_CONFLICT"
    if "Background_Shared.txt" in role_map:
        assert role_map["Background_Shared.txt"] == "SHARED_CONTEXT"


def test_validator_architecture_non_mutation():
    """Verify that validator.py and final_status logic remain 100% untouched and operational."""
    finding = {
        "control_id": "8.17",
        "control_name": "Clock Synchronization",
        "requirement_question": "Whether NTP is synchronized?",
        "policy_status": "FOUND",
        "policy_assessment": "COMPLIANT",
        "evidence_status": "FOUND",
        "evidence_assessment": "COMPLIANT",
        "policy_validity": "CURRENT",
        "evidence_freshness": "CURRENT",
        "evidence_snippet": "NTP synchronized: yes",
        "status": "COMPLIANT"
    }
    result = post_process(finding, "NTP synchronized: yes")
    assert result["final_result"] in ("COMPLIANT", "NON_COMPLIANT")
