"""
Unit tests for NIST SP 800-30 Rev. 1 Risk Assessment & Deterministic P1-P4 Project Severity Mapping.
Tests the 5 required test cases specified in the prompt:
1. Test 1 — Policy only: Policy FOUND + Evidence NOT_FOUND + Status NON_COMPLIANT derives severity from risk, NOT hardcoded P3.
2. Test 2 — Low-risk finding: Likelihood LOW + Impact MODERATE -> Risk LOW -> Severity P4 Low.
3. Test 3 — High-risk finding: Likelihood HIGH + Impact HIGH -> Risk CRITICAL -> Severity P1 Critical.
4. Test 4 — Compliant finding: Status COMPLIANT -> Severity N/A.
5. Test 5 — False positive finding: Status FALSE_POSITIVE -> Severity N/A.
"""
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.core.validator import post_process, evaluate_nist_risk_and_severity


class TestNistSeverityEngine(unittest.TestCase):

    def test_scenario_1_policy_only_risk_derived_severity(self):
        """Test 1: Policy FOUND + Evidence NOT_FOUND calculates severity from NIST risk, NOT forced P3."""
        finding = {
            "control_id": "5.15 Access Control",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "NOT_FOUND",
            "evidence_assessment": "NON_COMPLIANT",
            "evidence_quote": "Security will audit registration logs daily.",
            "source_files": "ID_Badge_and_Facility_Access_Policy_V17.0.pdf",
            "likelihood": "LOW",
            "impact": "MODERATE"
        }
        document_text = "Security will audit registration logs daily."

        result = post_process(finding, document_text)

        self.assertEqual(result["status"], "NON_COMPLIANT")
        self.assertEqual(result["likelihood"], "LOW")
        self.assertEqual(result["impact"], "MODERATE")
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["severity"], "P4 Low")

    def test_scenario_2_low_risk_finding_yields_p4_low(self):
        """Test 2: Likelihood LOW + Impact MODERATE -> Risk LOW -> Severity P4 Low."""
        finding = {
            "control_id": "5.15 Access Control",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "NOT_FOUND",
            "likelihood": "LOW",
            "impact": "MODERATE",
            "evidence_quote": "Policy statement text."
        }
        result = evaluate_nist_risk_and_severity(finding)

        self.assertEqual(result["likelihood"], "LOW")
        self.assertEqual(result["impact"], "MODERATE")
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["severity"], "P4 Low")

    def test_scenario_3_high_risk_finding_yields_p1_critical(self):
        """Test 3: Likelihood HIGH + Impact HIGH -> Risk CRITICAL -> Severity P1 Critical."""
        finding = {
            "control_id": "5.15 Access Control",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "NOT_FOUND",
            "likelihood": "HIGH",
            "impact": "HIGH",
            "evidence_quote": "Unrestricted administrative root credentials exposed."
        }
        result = evaluate_nist_risk_and_severity(finding)

        self.assertEqual(result["likelihood"], "HIGH")
        self.assertEqual(result["impact"], "HIGH")
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertEqual(result["severity"], "P1 Critical")

    def test_scenario_4_compliant_finding_yields_na_severity(self):
        """Test 4: Status COMPLIANT -> Severity N/A."""
        finding = {
            "control_id": "5.15 Access Control",
            "status": "COMPLIANT",
            "final_result": "COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "FOUND",
            "evidence_quote": "19-Aug-2026 — Registration logs audited."
        }
        result = evaluate_nist_risk_and_severity(finding)

        self.assertEqual(result["severity"], "N/A")

    def test_scenario_5_false_positive_finding_yields_na_severity(self):
        """Test 5: Status FALSE_POSITIVE -> Severity N/A."""
        finding = {
            "control_id": "5.15 Access Control",
            "status": "FALSE_POSITIVE",
            "policy_status": "NOT_FOUND",
            "evidence_status": "NOT_FOUND",
            "evidence_quote": "NOT_FOUND"
        }
        result = evaluate_nist_risk_and_severity(finding)

        self.assertEqual(result["status"], "FALSE_POSITIVE")
        self.assertEqual(result["severity"], "N/A")


if __name__ == "__main__":
    unittest.main()
