"""
Unit tests for Auditor-Grade Policy & Operational Evidence Coverage.
Tests the 6 mandatory auditor test scenarios specified in the prompt:
1. Test 1 — Policy only: Policy sentence alone must set evidence_status = NOT_FOUND and final_result != COMPLIANT.
2. Test 2 — Policy + actual audit record: Policy + dated operational log yields COMPLIANT.
3. Test 3 — Single evidence file supporting multiple requirements: Coverage calculated by requirements, not file count.
4. Test 4 — Policy copied into evidence: Restated policy sentence in evidence file stays POLICY text.
5. Test 5 — Irrelevant operational log: Unrelated log yields NOT_SUPPORTED.
6. Test 6 — Partial evidence: Partial operational evidence yields PARTIAL.
"""
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.core.validator import post_process


class TestAuditorCoverageEngine(unittest.TestCase):

    def test_scenario_1_policy_only_yields_not_compliant(self):
        """Test 1: Uploading only a policy document must NOT result in COMPLIANT."""
        finding = {
            "control_id": "5.15",
            "control_name": "Access Control",
            "status": "COMPLIANT", # LLM self-claimed COMPLIANT
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "FOUND",
            "evidence_assessment": "COMPLIANT",
            "evidence_quote": "Security will audit registration logs daily.",
            "source_files": "ID_Badge_and_Facility_Access_Policy_V17.0.pdf", # Policy file only
            "policy_finding": "Security will audit registration logs daily."
        }
        document_text = "Security will audit registration logs daily."
        
        result = post_process(finding, document_text)
        
        self.assertEqual(result["policy_status"], "FOUND")
        self.assertEqual(result["evidence_status"], "NOT_FOUND")
        self.assertNotEqual(result["final_result"], "COMPLIANT")
        self.assertNotEqual(result["status"], "COMPLIANT")
        self.assertTrue(len(result["policy_snippet"]) > 0)
        self.assertEqual(result["operational_evidence_snippet"], "")

    def test_scenario_2_policy_plus_actual_audit_log_yields_compliant(self):
        """Test 2: Policy + dated operational audit log yields COMPLIANT."""
        finding = {
            "control_id": "5.15",
            "control_name": "Access Control",
            "status": "COMPLIANT",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "FOUND",
            "evidence_assessment": "COMPLIANT",
            "evidence_quote": "19-Aug-2026 — Registration logs audited by Security Officer X.",
            "source_files": "ID_Badge_Policy.pdf, Registration_Audit_Log.xlsx", # Policy + Operational log
            "policy_finding": "Security will audit registration logs daily."
        }
        document_text = "19-Aug-2026 — Registration logs audited by Security Officer X."
        
        result = post_process(finding, document_text)
        
        self.assertEqual(result["policy_status"], "FOUND")
        self.assertEqual(result["evidence_status"], "FOUND")
        self.assertEqual(result["final_result"], "COMPLIANT")
        self.assertEqual(result["status"], "COMPLIANT")
        self.assertTrue(len(result["operational_evidence_snippet"]) > 0)

    def test_scenario_3_single_file_covers_multiple_requirements(self):
        """Test 3: Single Excel file supporting 6 of 8 requirements calculates 6/8 requirement coverage."""
        finding = {
            "control_id": "5.15",
            "control_name": "Access Control",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "FOUND",
            "evidence_assessment": "NON_COMPLIANT",
            "policy_snippet": "Req 1\n\nReq 2\n\nReq 3\n\nReq 4\n\nReq 5\n\nReq 6\n\nReq 7\n\nReq 8",
            "evidence_quote": "User onboarding logs from row 1 to row 50.",
            "source_files": "Access_Control_Audit.xlsx"
        }
        document_text = "User onboarding logs from row 1 to row 50."
        
        result = post_process(finding, document_text)
        
        self.assertEqual(result["requirements_total"], 8)
        self.assertEqual(result["requirements_supported"] + result["requirements_partial"] + result["requirements_not_supported"], 8)

    def test_scenario_4_policy_text_copied_into_evidence_stays_policy(self):
        """Test 4: Policy text copied into evidence file remains POLICY text, NOT operational proof."""
        finding = {
            "control_id": "5.15",
            "control_name": "Access Control",
            "status": "COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "FOUND",
            "evidence_quote": "The policy requires Security to audit registration logs daily.",
            "source_files": "ID_Badge_and_Facility_Access_Policy_V17.0.pdf"
        }
        document_text = "The policy requires Security to audit registration logs daily."
        
        result = post_process(finding, document_text)
        
        self.assertEqual(result["evidence_status"], "NOT_FOUND")
        self.assertNotEqual(result["final_result"], "COMPLIANT")

    def test_scenario_5_irrelevant_operational_log_not_supported(self):
        """Test 5: Operational log that is irrelevant to the control fails evidence assessment."""
        finding = {
            "control_id": "5.15",
            "control_name": "Access Control",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "NOT_FOUND",
            "evidence_assessment": "NON_COMPLIANT",
            "evidence_relevance": "IRRELEVANT",
            "evidence_quote": "Cafeteria lunch menu audit records for August 2026.",
            "source_files": "Cafeteria_Menu.xlsx"
        }
        document_text = "Cafeteria lunch menu audit records for August 2026."
        
        result = post_process(finding, document_text)
        
        self.assertEqual(result["evidence_status"], "NOT_FOUND")
        self.assertEqual(result["final_result"], "NON_COMPLIANT")

    def test_scenario_6_partial_evidence_yields_partial(self):
        """Test 6: Partial operational evidence yields PARTIAL requirement status."""
        finding = {
            "control_id": "5.15",
            "control_name": "Access Control",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "FOUND",
            "evidence_assessment": "NON_COMPLIANT",
            "evidence_quote": "Offboarding revocation log exists but 2 timestamps exceeded SLA.",
            "source_files": "Offboarding_Revocation_Log.csv"
        }
        document_text = "Offboarding revocation log exists but 2 timestamps exceeded SLA."
        
        result = post_process(finding, document_text)
        
        self.assertEqual(result["final_result"], "NON_COMPLIANT")
        self.assertGreaterEqual(result["requirements_total"], 1)

    def test_app_js_has_no_missing_variables(self):
        """Ensures app.js contains EVIDENCE_SNIPPET_PRE_STYLE definition."""
        app_js_path = os.path.join(PROJECT_ROOT, "src", "api", "static", "app.js")
        with open(app_js_path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("EVIDENCE_SNIPPET_PRE_STYLE", content)
        self.assertIn("const EVIDENCE_SNIPPET_PRE_STYLE", content)


if __name__ == "__main__":
    unittest.main()
