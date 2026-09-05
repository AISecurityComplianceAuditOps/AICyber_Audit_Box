# -*- coding: utf-8 -*-
"""
Automated Test Suite: 11 Audit Scenarios for Policy vs. Evidence Audit Reasoning
Tests deterministic validation, scope resolution, date validity, and policy/evidence separation.
"""

import os
import sys

sys.path.append(os.getcwd())

from src.core.validator import post_process, validate_only
from src.core.controls_data import USE_CASES

print("=" * 80)
print("RUNNING AUTOMATED TEST SUITE: 11 AUDIT SCENARIOS")
print("=" * 80)

passed = 0
failed = 0

def assert_test(condition, test_name, details=""):
    global passed, failed
    if condition:
        print(f"  [PASS] {test_name}")
        passed += 1
    else:
        print(f"  [FAIL] {test_name}: {details}")
        failed += 1


# ── TEST CASE 1: Physical Access Policy Only (Motorola ID Badge Policy) ──
print("\n--- Test Case 1: Physical access policy only (Motorola ID Badge Policy) ---")
doc_text_1 = """
ID Badge and Facility Access Policy V17.0
2.10. Visitors: All visitors shall be pre-registered on a visitor management system i.e. BreezN or Kastle.
2.11. Access Control: All individuals must display their Motorola Solutions ID badge when entering a Motorola Solutions facility. Access must be controlled by security personnel or receptionists, through the use of electronic card access systems.
"""
finding_1 = {
    "control_id": "5.15 Access Control",
    "policy_status": "FOUND",
    "policy_assessment": "COMPLIANT",
    "policy_name": "ID Badge and Facility Access Policy",
    "policy_clause": "Section 2.10, 2.11",
    "policy_validity": "CURRENT",
    "policy_gap": "No policy gap identified.",
    "evidence_status": "NOT_FOUND",
    "evidence_assessment": "NON_COMPLIANT",
    "evidence_gap": "No operational evidence was provided to demonstrate implementation.",
    "evidence_quote": "",
    "status": "NON_COMPLIANT",
    "final_result": "NON_COMPLIANT"
}
res_1 = post_process(finding_1, doc_text_1, {"5.15": ["Access Control Policy"]})
assert_test(res_1.get("policy_status") == "FOUND", "Case 1: Policy Status is FOUND")
assert_test(res_1.get("policy_assessment") == "COMPLIANT", "Case 1: Policy Assessment is COMPLIANT")
assert_test(res_1.get("policy_present") == "Compliant", "Case 1: UI Policy Present is Compliant")
assert_test(res_1.get("evidence_status") == "NOT_FOUND", "Case 1: Evidence Status is NOT_FOUND")
assert_test(res_1.get("evidence_present") == "Not Found", "Case 1: UI Evidence Present is Not Found")
assert_test(res_1.get("status") == "NON_COMPLIANT", "Case 1: Final Status is strictly NON_COMPLIANT")
assert_test(res_1.get("status") != "FALSE_POSITIVE", "Case 1: Status is NOT FALSE_POSITIVE")
assert_test("operational evidence" in res_1.get("recommendation", "").lower(), "Case 1: Recommendation targets missing operational evidence")


# ── TEST CASE 2: Physical Access Policy + Actual Badge Logs ──
print("\n--- Test Case 2: Physical access policy + actual badge/turnstile swipe logs ---")
doc_text_2 = """
ID Badge and Facility Access Policy:
All personnel must swipe their assigned RFID badges at turnstiles.

Lenel OnGuard Physical Access Logs:
14-Aug-2026 08:30:12 - Turnstile 01: Authorized swipe employee EMP-4920.
"""
finding_2 = {
    "control_id": "5.15 Access Control",
    "policy_status": "FOUND",
    "policy_assessment": "COMPLIANT",
    "policy_validity": "CURRENT",
    "evidence_status": "FOUND",
    "evidence_assessment": "COMPLIANT",
    "evidence_freshness": "CURRENT",
    "evidence_relevance": "DIRECT",
    "evidence_quote": "14-Aug-2026 08:30:12 - Turnstile 01: Authorized swipe employee EMP-4920.",
    "status": "COMPLIANT",
    "final_result": "COMPLIANT"
}
res_2 = post_process(finding_2, doc_text_2, {"5.15": ["Access Control Policy"]})
assert_test(res_2.get("policy_assessment") == "COMPLIANT", "Case 2: Policy Assessment is COMPLIANT")
assert_test(res_2.get("evidence_assessment") == "COMPLIANT", "Case 2: Evidence Assessment is COMPLIANT")
assert_test(res_2.get("status") == "COMPLIANT", "Case 2: Final Status is COMPLIANT")


# ── TEST CASE 3: Physical Access Policy + Sufficient Operational Records ──
print("\n--- Test Case 3: Physical access policy + sufficient operational visitor & access records ---")
doc_text_3 = """
Visitor and Facility Security Standard:
All visitors must be logged and escorted. Badge access required for all facility areas.

Operational Evidence:
Visitor Management System Log on 12-Aug-2026: Visitor John Doe checked in with escort badge V-102.
Card Access Audit Report 12-Aug-2026: 100% badge swipe verification across all perimeter access points.
"""
finding_3 = {
    "control_id": "5.15 Access Control",
    "policy_status": "FOUND",
    "policy_assessment": "COMPLIANT",
    "policy_validity": "CURRENT",
    "evidence_status": "FOUND",
    "evidence_assessment": "COMPLIANT",
    "evidence_freshness": "CURRENT",
    "evidence_relevance": "DIRECT",
    "evidence_quote": "Visitor Management System Log on 12-Aug-2026: Visitor John Doe checked in with escort badge V-102.",
    "status": "COMPLIANT",
    "final_result": "COMPLIANT"
}
res_3 = post_process(finding_3, doc_text_3, {"5.15": ["Access Control Policy"]})
assert_test(res_3.get("status") == "COMPLIANT", "Case 3: Sufficient operational evidence produces COMPLIANT")


# ── TEST CASE 4: Physical Access Policy Evaluated Against 5.15 (No Manufactured Gap) ──
print("\n--- Test Case 4: Physical access policy against 5.15 (No manufactured logical IT gap) ---")
finding_4 = {
    "control_id": "5.15 Access Control",
    "policy_status": "FOUND",
    "policy_assessment": "COMPLIANT",
    "policy_gap": "No policy gap identified.",
    "evidence_status": "NOT_FOUND",
    "evidence_assessment": "NON_COMPLIANT",
    "evidence_gap": "No operational evidence was provided to demonstrate implementation.",
    "status": "NON_COMPLIANT"
}
res_4 = post_process(finding_4, doc_text_1, {"5.15": ["Access Control Policy"]})
assert_test(res_4.get("policy_assessment") == "COMPLIANT", "Case 4: Physical policy has COMPLIANT policy assessment")
assert_test(res_4.get("policy_gap") == "No policy gap identified.", "Case 4: No logical IT gap manufactured")


# ── TEST CASE 5: Unrelated Document (Applicable Control, Missing Evidence) ──
print("\n--- Test Case 5: Unrelated document for applicable control ---")
doc_text_5 = "Office Catering Invoice #9482. Total: $450.00."
finding_5 = {
    "control_id": "5.15 Access Control",
    "policy_status": "NOT_FOUND",
    "policy_assessment": "NON_COMPLIANT",
    "policy_gap": "Document is an invoice and contains no access control policy.",
    "evidence_status": "NOT_FOUND",
    "evidence_assessment": "NON_COMPLIANT",
    "evidence_gap": "No access control evidence found.",
    "status": "NON_COMPLIANT"
}
res_5 = post_process(finding_5, doc_text_5, {"5.15": ["Access Control Policy"]})
assert_test(res_5.get("status") == "NON_COMPLIANT", "Case 5: Unrelated document is NON_COMPLIANT")
assert_test(res_5.get("status") != "FALSE_POSITIVE", "Case 5: Unrelated document is NOT FALSE_POSITIVE")


# ── TEST CASE 6: Control Genuinely Outside Agreed Audit Scope ──
print("\n--- Test Case 6: Control genuinely outside agreed audit scope ---")
finding_6 = {
    "control_id": "8.28 Secure Coding",
    "status": "FALSE_POSITIVE",
    "final_result": "FALSE_POSITIVE",
    "policy_status": "NOT_FOUND",
    "evidence_status": "NOT_FOUND",
    "reasoning": "Organization strictly purchases COTS software with no in-house software development. Control is out of scope."
}
res_6 = post_process(finding_6, "General company overview", {})
assert_test(res_6.get("status") == "FALSE_POSITIVE", "Case 6: Out of scope control remains FALSE_POSITIVE")
assert_test(res_6.get("severity") == "N/A", "Case 6: FALSE_POSITIVE severity is N/A")


# ── TEST CASE 7: Backup Policy Stating "Daily Backups" Without Backup Logs ──
print("\n--- Test Case 7: Backup policy without operational backup logs ---")
doc_text_7 = "Backup Policy: System administrators shall perform full automated database backups daily at 02:00 UTC."
finding_7 = {
    "control_id": "8.13 Information Backup",
    "policy_status": "FOUND",
    "policy_assessment": "COMPLIANT",
    "policy_gap": "No policy gap identified.",
    "evidence_status": "NOT_FOUND",
    "evidence_assessment": "NON_COMPLIANT",
    "evidence_gap": "No operational evidence was provided to demonstrate implementation.",
    "status": "NON_COMPLIANT"
}
res_7 = post_process(finding_7, doc_text_7, {"8.13": ["Backup Policy"]})
assert_test(res_7.get("policy_assessment") == "COMPLIANT", "Case 7: Backup Policy Assessment is COMPLIANT")
assert_test(res_7.get("evidence_status") == "NOT_FOUND", "Case 7: Operational Evidence is NOT_FOUND")
assert_test(res_7.get("status") == "NON_COMPLIANT", "Case 7: Final Status is NON_COMPLIANT")


# ── TEST CASE 8: Backup Policy + Daily Backup Execution Reports ──
print("\n--- Test Case 8: Backup policy + daily backup execution reports ---")
doc_text_8 = """
Backup Policy:
System administrators shall perform full automated database backups daily at 02:00 UTC.

Veeam Backup & Replication Job Log:
Job: DB_PROD_DAILY_FULL - Status: Success - Completed: 15-Aug-2026 02:24:10 UTC - Size: 1.4TB
"""
finding_8 = {
    "control_id": "8.13 Information Backup",
    "policy_status": "FOUND",
    "policy_assessment": "COMPLIANT",
    "policy_validity": "CURRENT",
    "evidence_status": "FOUND",
    "evidence_assessment": "COMPLIANT",
    "evidence_freshness": "CURRENT",
    "evidence_relevance": "DIRECT",
    "evidence_quote": "Job: DB_PROD_DAILY_FULL - Status: Success - Completed: 15-Aug-2026 02:24:10 UTC - Size: 1.4TB",
    "status": "COMPLIANT",
    "final_result": "COMPLIANT"
}
res_8 = post_process(finding_8, doc_text_8, {"8.13": ["Backup Policy"]})
assert_test(res_8.get("status") == "COMPLIANT", "Case 8: Backup Policy + Execution Log is COMPLIANT")


# ── TEST CASE 9: Old Policy With No Stated Expiry Date ──
print("\n--- Test Case 9: Old policy with no stated expiry date ---")
doc_text_9 = "Information Security Policy Document. Published: 10-Jan-2018. Approved by CISO."
finding_9 = {
    "control_id": "5.1 Policies for Information Security",
    "policy_status": "FOUND",
    "policy_assessment": "COMPLIANT",
    "policy_effective_date": "2018-01-10",
    "policy_validity": "UNKNOWN",
    "evidence_status": "FOUND",
    "evidence_assessment": "COMPLIANT",
    "evidence_freshness": "UNKNOWN",
    "evidence_relevance": "DIRECT",
    "evidence_quote": "Information Security Policy Document. Published: 10-Jan-2018. Approved by CISO.",
    "status": "COMPLIANT",
    "final_result": "COMPLIANT"
}
res_9 = post_process(finding_9, doc_text_9, {"5.1": ["Approved information security policy framework document signed by senior management."]})
assert_test(res_9.get("policy_validity") in ("UNKNOWN", "CURRENT"), f"Case 9: Policy validity is not auto-expired: {res_9.get('policy_validity')}")
assert_test(res_9.get("status") == "COMPLIANT", "Case 9: Final status is COMPLIANT when no expiry is violated")


# ── TEST CASE 10: Policy + Partial Operational Evidence ──
print("\n--- Test Case 10: Policy + partial operational evidence (covers only 1 part) ---")
doc_text_10 = """
Access Control Policy:
Facility access requires turnstile badges for general entry and biometric scanners for high-security server rooms.

Operational Log:
General Visitor Log 10-Aug-2026: 5 visitors escorted at reception.
"""
finding_10 = {
    "control_id": "5.15 Access Control",
    "policy_status": "FOUND",
    "policy_assessment": "COMPLIANT",
    "policy_gap": "No policy gap identified.",
    "evidence_status": "FOUND",
    "evidence_assessment": "NON_COMPLIANT",
    "evidence_relevance": "PARTIAL",
    "evidence_gap": "No operational evidence was provided for biometric server room access controls.",
    "evidence_quote": "General Visitor Log 10-Aug-2026: 5 visitors escorted at reception.",
    "status": "NON_COMPLIANT"
}
res_10 = post_process(finding_10, doc_text_10, {"5.15": ["Access Control Policy"]})
assert_test(res_10.get("policy_assessment") == "COMPLIANT", "Case 10: Policy Assessment remains COMPLIANT")
assert_test(res_10.get("evidence_assessment") == "NON_COMPLIANT", "Case 10: Evidence Assessment is NON_COMPLIANT")
assert_test(res_10.get("status") == "NON_COMPLIANT", "Case 10: Final Status is NON_COMPLIANT")


# ── TEST CASE 11: Excel Scoping Mode: Policy Stated in Evidence Column ──
print("\n--- Test Case 11: Excel mode with policy in evidence column (not converted to logs) ---")
doc_text_11 = "Security Operations Standard: Security will audit registration logs daily."
finding_11 = {
    "control_id": "5.15 Access Control",
    "policy_status": "FOUND",
    "policy_assessment": "COMPLIANT",
    "policy_gap": "No policy gap identified.",
    "evidence_status": "NOT_FOUND",
    "evidence_assessment": "NON_COMPLIANT",
    "evidence_gap": "No operational evidence was provided to demonstrate implementation (stated policy is not operational proof).",
    "status": "NON_COMPLIANT"
}
res_11 = post_process(finding_11, doc_text_11, {"5.15": ["Access Control Policy"]})
assert_test(res_11.get("policy_assessment") == "COMPLIANT", "Case 11: Policy Assessment is COMPLIANT")
assert_test(res_11.get("evidence_status") == "NOT_FOUND", "Case 11: Stated policy is NOT treated as operational evidence")
assert_test(res_11.get("status") == "NON_COMPLIANT", "Case 11: Final Status is NON_COMPLIANT")


# ── SUMMARY ──
print("\n" + "=" * 80)
print(f"AUTOMATED TEST RESULTS: {passed} PASSED, {failed} FAILED (TOTAL {passed + failed} CHECKS)")
print("=" * 80)

if failed > 0:
    sys.exit(1)
