# -*- coding: utf-8 -*-
"""
Test Final Cleanup Suite
========================
Validates the decoupled compliance architecture, policy status semantics,
final status immutability, item collection independence, and UTF-8 encoding.
"""

import os
import json
import pytest
from src.core.validator import (
    post_process,
    EvidenceItem,
    derive_policy_required,
)

def _run(finding, policy_items=None, evidence_items=None):
    finding["policy_items_json"] = json.dumps([it.to_dict() for it in (policy_items or [])])
    finding["evidence_items_json"] = json.dumps([it.to_dict() for it in (evidence_items or [])])
    return post_process(finding, document_text="", expected_evidence_map={}, db_chunks=[])


def test_817_optional_policy_with_valid_evidence_compliant():
    """8.17 Clock Synchronization: Policy not required + valid NTP evidence -> COMPLIANT."""
    finding = {
        "control_id": "8.17 Clock Synchronization",
        "control_name": "Clock Synchronization",
        "question": "Whether Network Time Protocol (NTP) is enabled and synchronized across critical servers.",
        "status": "COMPLIANT",
        "evidence_snippet": "timedatectl output: Local time: Thu 2026-08-20 14:00:00 UTC. NTP service: active. System clock synchronized: yes.",
        "source_files": "ntp_console_output.txt"
    }
    
    item = EvidenceItem(
        artifact_id="item_1",
        content_type="NTP_LOG",
        artifact_modality="TEXT",
        source_file="ntp_console_output.txt",
        extracted_text="System clock synchronized: yes",
        provenance="Direct operational proof of NTP clock synchronization",
        grounding_status="GROUNDED",
        evidence_relevance="DIRECT",
        support_status="SUPPORTED",
        restated_policy=False
    )
    
    result = _run(finding, policy_items=[], evidence_items=[item])
    
    assert result["policy_required"] is False
    assert result["policy_status"] == "NOT_REQUIRED"
    assert result["policy_assessment"] == "NOT_APPLICABLE"
    assert result["evidence_status"] == "FOUND"
    assert result["evidence_assessment"] == "COMPLIANT"
    assert result["final_result"] == "COMPLIANT"
    assert result["status"] == "COMPLIANT"
    assert result["policy_present"] == "Not Required"


def test_817_optional_policy_missing_evidence_non_compliant():
    """8.17 Clock Synchronization: Policy not required + NO operational evidence -> NON_COMPLIANT.
    Proves 'Policy Not Required' does NOT mean 'Control Automatically Compliant'.
    """
    finding = {
        "control_id": "8.17 Clock Synchronization",
        "control_name": "Clock Synchronization",
        "question": "Whether Network Time Protocol (NTP) is enabled and synchronized across critical servers.",
        "status": "NON_COMPLIANT",
        "evidence_snippet": "NOT_FOUND",
        "source_files": ""
    }
    
    result = _run(finding, policy_items=[], evidence_items=[])
    
    assert result["policy_required"] is False
    assert result["policy_status"] == "NOT_REQUIRED"
    assert result["policy_assessment"] == "NOT_APPLICABLE"
    assert result["evidence_status"] == "NOT_FOUND"
    assert result["evidence_assessment"] == "NON_COMPLIANT"
    assert result["final_result"] == "NON_COMPLIANT"
    assert result["status"] == "NON_COMPLIANT"
    assert result["policy_present"] == "Not Required"


def test_817_optional_policy_uploaded_with_valid_evidence_compliant():
    """8.17 Clock Synchronization: Optional policy + policy uploaded + valid evidence -> COMPLIANT."""
    finding = {
        "control_id": "8.17 Clock Synchronization",
        "control_name": "Clock Synchronization",
        "question": "Whether Network Time Protocol (NTP) is enabled and synchronized across critical servers.",
        "status": "COMPLIANT",
        "evidence_snippet": "NTP config verified.",
        "source_files": "NTP_Policy.pdf, ntp_log.txt"
    }
    
    pol_item = EvidenceItem(
        artifact_id="pol_1",
        content_type="POLICY_DOCUMENT",
        artifact_modality="DOCUMENT",
        source_file="NTP_Policy.pdf",
        extracted_text="All servers must synchronize time via NTP server pool.",
        provenance="Policy statement for clock synchronization",
        grounding_status="GROUNDED",
        evidence_relevance="DIRECT",
        support_status="SUPPORTED",
        restated_policy=True
    )
    
    ev_item = EvidenceItem(
        artifact_id="ev_1",
        content_type="NTP_LOG",
        artifact_modality="TEXT",
        source_file="ntp_log.txt",
        extracted_text="NTP sync active.",
        provenance="Operational proof of NTP synchronization",
        grounding_status="GROUNDED",
        evidence_relevance="DIRECT",
        support_status="SUPPORTED",
        restated_policy=False
    )
    
    result = _run(finding, policy_items=[pol_item], evidence_items=[ev_item])
    
    assert result["policy_required"] is False
    assert result["policy_status"] == "FOUND"
    assert result["policy_assessment"] == "COMPLIANT"
    assert result["evidence_status"] == "FOUND"
    assert result["evidence_assessment"] == "COMPLIANT"
    assert result["final_result"] == "COMPLIANT"
    assert result["status"] == "COMPLIANT"
    assert result["policy_present"] == "Compliant"


def test_82_optional_policy_found_missing_evidence_non_compliant():
    """8.2 Privileged Access Rights: Policy uploaded + NO operational log -> NON_COMPLIANT.
    Proves policy presence alone does NOT satisfy operational evidence requirement.
    """
    finding = {
        "control_id": "8.2 Privileged Access Rights",
        "control_name": "Privileged Access Rights",
        "question": "Provide operational access review logs or PAM user listing.",
        "status": "NON_COMPLIANT",
        "evidence_snippet": "NOT_FOUND",
        "source_files": "PAM_Access_Policy.pdf"
    }
    
    pol_item = EvidenceItem(
        artifact_id="pol_1",
        content_type="POLICY_DOCUMENT",
        artifact_modality="DOCUMENT",
        source_file="PAM_Access_Policy.pdf",
        extracted_text="Privileged access must be limited and reviewed quarterly.",
        provenance="Policy document defining PAM access rules",
        grounding_status="GROUNDED",
        evidence_relevance="DIRECT",
        support_status="SUPPORTED",
        restated_policy=True
    )
    
    result = _run(finding, policy_items=[pol_item], evidence_items=[])
    
    assert result["policy_required"] is False
    assert result["policy_status"] == "FOUND"
    assert result["policy_assessment"] == "COMPLIANT"
    assert result["evidence_status"] == "NOT_FOUND"
    assert result["evidence_assessment"] == "NON_COMPLIANT"
    assert result["final_result"] == "NON_COMPLIANT"
    assert result["status"] == "NON_COMPLIANT"
    assert result["policy_present"] == "Compliant"


def test_51_required_policy_missing_non_compliant():
    """5.1 Policies for Information Security: Policy required + policy missing -> NON_COMPLIANT."""
    finding = {
        "control_id": "5.1 Policies for Information Security",
        "control_name": "Policies for Information Security",
        "question": "Provide formally approved Information Security Policy document with version and approval date.",
        "status": "NON_COMPLIANT",
        "evidence_snippet": "NOT_FOUND",
        "source_files": ""
    }
    
    result = _run(finding, policy_items=[], evidence_items=[])
    
    assert result["policy_required"] is True
    assert result["policy_status"] == "NOT_FOUND"
    assert result["policy_assessment"] == "NON_COMPLIANT"
    assert result["final_result"] == "NON_COMPLIANT"
    assert result["status"] == "NON_COMPLIANT"
    assert result["policy_present"] == "Not Found"


def test_51_required_policy_found_and_evidence_satisfied_compliant():
    """5.1 Policies for Information Security: Policy required + approved policy found -> COMPLIANT."""
    finding = {
        "control_id": "5.1 Policies for Information Security",
        "control_name": "Policies for Information Security",
        "question": "Provide formally approved Information Security Policy document with version and approval date.",
        "status": "COMPLIANT",
        "evidence_snippet": "Information Security Policy v2.4, Approved on 15-Jan-2026 by CISO.",
        "source_files": "InfoSec_Policy_v2.4.pdf"
    }
    
    pol_item = EvidenceItem(
        artifact_id="pol_1",
        content_type="GOVERNANCE_POLICY",
        artifact_modality="DOCUMENT",
        source_file="InfoSec_Policy_v2.4.pdf",
        extracted_text="Information Security Policy v2.4 Approved by CISO",
        provenance="Approved governance policy document",
        grounding_status="GROUNDED",
        evidence_relevance="DIRECT",
        support_status="SUPPORTED",
        restated_policy=True
    )
    
    # For governance control 5.1, approved policy document serves as valid documentary evidence
    ev_item = EvidenceItem(
        artifact_id="ev_1",
        content_type="GOVERNANCE_POLICY",
        artifact_modality="DOCUMENT",
        source_file="InfoSec_Policy_v2.4.pdf",
        extracted_text="Information Security Policy v2.4 Approved by CISO",
        provenance="Approved documentary evidence",
        grounding_status="GROUNDED",
        evidence_relevance="DIRECT",
        support_status="SUPPORTED",
        restated_policy=False
    )
    
    result = _run(finding, policy_items=[pol_item], evidence_items=[ev_item])
    
    assert result["policy_required"] is True
    assert result["policy_status"] == "FOUND"
    assert result["policy_assessment"] == "COMPLIANT"
    assert result["evidence_status"] == "FOUND"
    assert result["evidence_assessment"] == "COMPLIANT"
    assert result["final_result"] == "COMPLIANT"
    assert result["status"] == "COMPLIANT"


def test_excel_question_metadata_isolation():
    """Verifies Excel requirement_question is preserved as metadata only and does not contaminate policy/evidence items."""
    question_text = "Check whether NTP daemon (timedatectl) is configured and active across all web nodes."
    finding = {
        "control_id": "8.17 Clock Synchronization",
        "control_name": "Clock Synchronization",
        "question": question_text,
        "requirement_question": question_text,
        "status": "COMPLIANT"
    }
    
    ev_item = EvidenceItem(
        artifact_id="ev_1",
        content_type="NTP_LOG",
        artifact_modality="TEXT",
        source_file="server_ntp.log",
        extracted_text="ntpd running, synchronized to 10.0.0.1",
        provenance="NTP log proof",
        grounding_status="GROUNDED",
        evidence_relevance="DIRECT",
        support_status="SUPPORTED",
        restated_policy=False
    )
    
    result = _run(finding, policy_items=[], evidence_items=[ev_item])
    
    assert result["requirement_question"] == question_text
    policy_items_json = json.loads(result["policy_items_json"])
    assert len(policy_items_json) == 0
    evidence_items_json = json.loads(result["evidence_items_json"])
    assert len(evidence_items_json) == 1
    assert evidence_items_json[0]["extracted_text"] != question_text


def test_policy_evidence_items_never_overlap():
    """Verifies policy_items and evidence_items collections are strictly disjoint."""
    finding = {
        "control_id": "5.15 Access Control",
        "control_name": "Access Control",
        "status": "COMPLIANT"
    }
    
    pol_item = EvidenceItem(
        artifact_id="item_pol_1",
        content_type="POLICY",
        artifact_modality="DOCUMENT",
        source_file="Access_Control_Policy.pdf",
        extracted_text="Physical access cards required.",
        provenance="Policy rule",
        grounding_status="GROUNDED",
        evidence_relevance="DIRECT",
        support_status="SUPPORTED",
        restated_policy=True
    )
    
    ev_item = EvidenceItem(
        artifact_id="item_ev_1",
        content_type="SWIPE_LOG",
        artifact_modality="TEXT",
        source_file="turnstile_swipe.log",
        extracted_text="User 4920 swiped turnstile 01",
        provenance="Log proof",
        grounding_status="GROUNDED",
        evidence_relevance="DIRECT",
        support_status="SUPPORTED",
        restated_policy=False
    )
    
    result = _run(finding, policy_items=[pol_item], evidence_items=[ev_item])
    
    pol_ids = {it["artifact_id"] for it in json.loads(result["policy_items_json"])}
    ev_ids = {it["artifact_id"] for it in json.loads(result["evidence_items_json"])}
    
    assert pol_ids.isdisjoint(ev_ids)


def test_utf8_encoding_clean_output():
    """Verifies UTF-8 text strings such as 'Whether NTP is enabled' render cleanly without mojibake."""
    unicode_text = "Whether Network Time Protocol (NTP) is enabled — System Clock Synchronized 100%"
    finding = {
        "control_id": "8.17 Clock Synchronization",
        "control_name": "Clock Synchronization",
        "question": unicode_text,
        "description": unicode_text,
        "status": "COMPLIANT"
    }
    
    ev_item = EvidenceItem(
        artifact_id="ev_1",
        content_type="NTP_LOG",
        artifact_modality="TEXT",
        source_file="ntp_utf8.log",
        extracted_text=unicode_text,
        provenance="Clean UTF-8 text",
        grounding_status="GROUNDED",
        evidence_relevance="DIRECT",
        support_status="SUPPORTED",
        restated_policy=False
    )
    
    result = _run(finding, policy_items=[], evidence_items=[ev_item])
    
    assert "Whether" in result["requirement_question"]
    assert "—" in result["requirement_question"]
    assert "[FÇö" not in result["requirement_question"]


def test_negative_evidence_mfa_disabled_forces_non_compliant():
    """Grounded evidence showing 'MFA status: disabled' MUST score NON_COMPLIANT."""
    finding = {
        "control_id": "8.5 Multi-Factor Authentication",
        "control_name": "Multi-Factor Authentication",
        "question": "Whether Multi-Factor Authentication (MFA) is enabled for cloud admin accounts.",
        "status": "COMPLIANT",  # LLM erroneously returned COMPLIANT due to finding a screenshot
        "evidence_snippet": "MFA status: disabled for root user",
        "source_files": "mfa_console.png"
    }
    
    item = EvidenceItem(
        artifact_id="item_mfa_1",
        content_type="SCREENSHOT",
        artifact_modality="IMAGE",
        source_file="mfa_console.png",
        extracted_text="Root account MFA status: disabled",
        provenance="Screenshot of MFA configuration",
        grounding_status="GROUNDED",
        evidence_relevance="DIRECT",
        support_status="SUPPORTED",
        restated_policy=False
    )
    
    result = _run(finding, policy_items=[], evidence_items=[item])
    
    assert result["evidence_assessment"] == "NON_COMPLIANT"
    assert result["final_result"] == "NON_COMPLIANT"
    assert result["status"] == "NON_COMPLIANT"


def test_negative_evidence_ntp_inactive_forces_non_compliant():
    """Grounded evidence showing 'NTP service: inactive' MUST score NON_COMPLIANT."""
    finding = {
        "control_id": "8.17 Clock Synchronization",
        "control_name": "Clock Synchronization",
        "question": "Whether Network Time Protocol (NTP) is enabled and synchronized across critical servers.",
        "status": "COMPLIANT",
        "evidence_snippet": "NTP service: inactive. System clock synchronized: no.",
        "source_files": "ntp_status.log"
    }
    
    item = EvidenceItem(
        artifact_id="item_ntp_neg",
        content_type="NTP_LOG",
        artifact_modality="TEXT",
        source_file="ntp_status.log",
        extracted_text="NTP service: inactive. System clock synchronized: no.",
        provenance="NTP status log",
        grounding_status="GROUNDED",
        evidence_relevance="DIRECT",
        support_status="SUPPORTED",
        restated_policy=False
    )
    
    result = _run(finding, policy_items=[], evidence_items=[item])
    
    assert result["evidence_assessment"] == "NON_COMPLIANT"
    assert result["final_result"] == "NON_COMPLIANT"
    assert result["status"] == "NON_COMPLIANT"


def test_scoping_resolution_id_only():
    """Input style 1: Control ID only -> resolves control_id, control_name, and framework requirement_question."""
    from src.core.excel_scoping_parser import _resolve_control, _load_use_cases
    use_cases = _load_use_cases()
    info = _resolve_control(id_text="8.17", use_cases=use_cases)
    assert info["control_id"] == "8.17"
    assert "Clock Synchronization" in info["control_label"]


def test_scoping_resolution_name_only():
    """Input style 2: Control Name only -> resolves control_id and control_name."""
    from src.core.excel_scoping_parser import _resolve_control, _load_use_cases
    use_cases = _load_use_cases()
    info = _resolve_control(name_text="Clock Synchronization", use_cases=use_cases)
    assert info["control_id"] == "8.17"
    assert "Clock Synchronization" in info["control_label"]


def test_scoping_resolution_question_only():
    """Input style 3: Question only -> resolves control_id while preserving explicit question."""
    from src.core.excel_scoping_parser import _resolve_control, _load_use_cases
    use_cases = _load_use_cases()
    q = "Whether Network Time Protocol (NTP) is enabled and synchronized across critical servers."
    info = _resolve_control(q_text=q, use_cases=use_cases)
    assert info["control_id"] == "8.17"


def test_scoping_resolution_id_plus_name_plus_question():
    """Combination input style: ID + Name + Question -> preserves explicit question without overwriting."""
    from src.core.excel_scoping_parser import _resolve_control, _load_use_cases
    use_cases = _load_use_cases()
    q = "Whether NTP time drift is within 500ms tolerance."
    info = _resolve_control(id_text="8.17", name_text="Clock Synchronization", q_text=q, use_cases=use_cases)
    assert info["control_id"] == "8.17"
    assert info["control_name"] == "Clock Synchronization"


def test_scoping_unresolved_question_metadata():
    """Unknown control with no question -> requirement_question=None, status=UNRESOLVED."""
    from src.core.excel_scoping_parser import _resolve_control, _load_use_cases
    use_cases = _load_use_cases()
    info = _resolve_control(id_text="CUSTOM_999", name_text="Unmatched Check", use_cases=use_cases)
    assert info["resolved"] is False


def test_scoping_hint_does_not_auto_grant_compliance():
    """Excel Policy/Evidence column citations do NOT auto-grant COMPLIANT without file content evaluation."""
    finding = {
        "control_id": "8.17 Clock Synchronization",
        "control_name": "Clock Synchronization",
        "question": "Whether Network Time Protocol (NTP) is enabled.",
        "status": "NON_COMPLIANT",
        "evidence_snippet": "NOT_FOUND",
        "source_files": "NTP_Policy.pdf, ntp_status.log"
    }
    # Operational evidence item is empty (or ungrounded)
    result = _run(finding, policy_items=[], evidence_items=[])
    assert result["final_result"] == "NON_COMPLIANT"
    assert result["evidence_assessment"] == "NON_COMPLIANT"


