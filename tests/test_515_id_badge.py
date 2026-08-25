# -*- coding: utf-8 -*-
"""
Verification of ISO 27001 Control 5.15 (Access Control) with ID Badge evidence.
Tests both policy statement and operational badge verification according to AGENTS.md rules.
"""

import os
import sys

sys.path.append(os.getcwd())

from src.core.validator import validate_only
from src.core.controls_data import USE_CASES

print("=" * 70)
print("TESTING ISO 27001 5.15 ACCESS CONTROL WITH ID BADGE EVIDENCE")
print("=" * 70)

# Control 5.15 definition
use_case_515 = next((uc for uc in USE_CASES if str(uc.get("use_case", "")).startswith("5.15")), None)
print(f"[+] Control 5.15 Found: {use_case_515['use_case']} | Label: {use_case_515.get('label')}")

# Scenario 1: Document containing BOTH Policy rule and Operational RFID Badge Evidence
doc_text_combined = """
ISMS Access Control Policy (Clause 4.2):
Access to organization facilities, server rooms, and information assets must be authorized, authenticated, and controlled. All personnel must wear and swipe their assigned RFID Photo ID Badges at entry turnstiles and secure area doors. Visitor escort procedures are strictly enforced.

Operational Implementation Evidence:
Physical access logs from the Lenel OnGuard automated badge access system on 14-Aug-2026 show authorized badge swipe entries at Main Facility Turnstile 01 and Server Room Door 02 for employees EMP-4920 and EMP-1184.
"""

finding_compliant = {
    "control_id": "5.15 Access Control",
    "policy_status": "FOUND",
    "policy_assessment": "COMPLIANT",
    "policy_name": "ISMS Access Control Policy",
    "policy_clause": "Clause 4.2",
    "policy_validity": "CURRENT",
    "evidence_status": "FOUND",
    "evidence_assessment": "COMPLIANT",
    "evidence_freshness": "CURRENT",
    "evidence_relevance": "DIRECT",
    "evidence_quote": "Physical access logs from the Lenel OnGuard automated badge access system on 14-Aug-2026 show authorized badge swipe entries at Main Facility Turnstile 01 and Server Room Door 02 for employees EMP-4920 and EMP-1184.",
    "evidence_snippet": "Physical access logs from the Lenel OnGuard automated badge access system on 14-Aug-2026 show authorized badge swipe entries at Main Facility Turnstile 01 and Server Room Door 02 for employees EMP-4920 and EMP-1184.",
    "status": "COMPLIANT",
    "final_result": "COMPLIANT"
}

from src.core.validator import post_process

res1 = post_process(finding_compliant, doc_text_combined, {"5.15": str(use_case_515.get("expected", ""))})

print("\n--- TEST CASE 1: ID Badge (Policy Rule + Operational Badge Swipe Evidence) ---")
print(f"  Policy Status     : {res1.get('policy_status')}")
print(f"  Evidence Status   : {res1.get('evidence_status')}")
print(f"  Evidence Snippet  : {res1.get('evidence_snippet')[:100]}...")
print(f"  FINAL STATUS      : {res1.get('status')} (Expected: COMPLIANT)")
if res1.get('status') == "COMPLIANT":
    print("  -> PASSED: 5.15 is correctly marked COMPLIANT with ID badge evidence! [OK]")
else:
    print(f"  -> FAILED: Got {res1.get('status')}")

# Scenario 2: Only Badge Screenshot (No documented Policy statement)
finding_no_policy = {
    "control_id": "5.15 Access Control",
    "policy_status": "NOT_FOUND",
    "policy_assessment": "NON_COMPLIANT",
    "evidence_status": "FOUND",
    "evidence_assessment": "COMPLIANT",
    "evidence_quote": "Physical access logs from the Lenel OnGuard automated badge access system on 14-Aug-2026 show authorized badge swipe entries at Main Facility Turnstile 01 and Server Room Door 02 for employees EMP-4920 and EMP-1184.",
    "evidence_snippet": "Physical access logs from the Lenel OnGuard automated badge access system on 14-Aug-2026 show authorized badge swipe entries at Main Facility Turnstile 01 and Server Room Door 02 for employees EMP-4920 and EMP-1184.",
    "status": "COMPLIANT", # LLM claims COMPLIANT without policy
    "final_result": "COMPLIANT"
}

res2 = post_process(finding_no_policy, doc_text_combined, {"5.15": str(use_case_515.get("expected", ""))})

print("\n--- TEST CASE 2: ID Badge (Operational Badge Swipe Only, Missing Policy) ---")
print(f"  Policy Status     : {res2.get('policy_status')}")
print(f"  Evidence Status   : {res2.get('evidence_status')}")
print(f"  FINAL STATUS      : {res2.get('status')} (Expected: NON_COMPLIANT)")
if res2.get('status') == "NON_COMPLIANT":
    print("  -> PASSED: Policy vs Evidence rule correctly required policy document! [OK]")
else:
    print(f"  -> FAILED: Got {res2.get('status')}")

print("\n" + "=" * 70)
print("5.15 ID BADGE VERIFICATION COMPLETE")
print("=" * 70)
