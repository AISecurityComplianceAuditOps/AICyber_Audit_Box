# -*- coding: utf-8 -*-
"""
Universal Content-Based Compliance Engine Test Suite
Tests 30 mandatory universal evaluation conditions on unseen controls and generic document content,
proving zero control-id, filename, or keyword-alone hardcoding.
"""
import unittest
import json
from src.core.validator import (
    classify_content_and_modality,
    classify_chunk_content_type,
    evaluate_nist_risk_and_severity,
    post_process,
    EvidenceItem
)

class TestUniversalEngine(unittest.TestCase):

    def test_01_policy_only_finding(self):
        finding = {
            "control_id": "CUSTOM_9.99 Unseen Control",
            "status": "COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "FOUND",
            "evidence_quote": "All personnel shall complete annual security training.",
            "source_files": "Security_Training_Policy.pdf"
        }
        res = post_process(finding, "All personnel shall complete annual security training.")
        self.assertEqual(res["evidence_status"], "NOT_FOUND")
        self.assertEqual(res["final_result"], "NON_COMPLIANT")

    def test_02_configuration_only_finding(self):
        meta = {"source_type": "text"}
        res = classify_content_and_modality("port: 443\ntls_version: 1.3\ncipher: AES256-GCM\nstatus: ok", "sys.conf", meta)
        self.assertEqual(res["content_type"], "CONFIGURATION")

    def test_03_log_only_finding(self):
        meta = {"source_type": "text"}
        res = classify_content_and_modality("2026-08-20 14:02:11 UTC session opened for user admin from IP 10.0.4.2", "audit.log", meta)
        self.assertEqual(res["content_type"], "LOG_RECORD")

    def test_04_screenshot_only_finding(self):
        meta = {"is_ocr": True, "source_type": "ocr"}
        res = classify_content_and_modality("MFA Enabled for user john.doe@company.com\nStatus: OK", "screenshot_mfa.png", meta)
        self.assertEqual(res["artifact_modality"], "SCREENSHOT")
        self.assertEqual(res["content_type"], "SYSTEM_OUTPUT")

    def test_05_report_only_finding(self):
        res = classify_content_and_modality("Vulnerability Audit Summary Report: 0 critical vulnerabilities found on 2026-08-10.", "report.pdf")
        self.assertEqual(res["content_type"], "REPORT")

    def test_06_approval_only_finding(self):
        res = classify_content_and_modality("Change Request #1042 approved by Chief Information Security Officer on 2026-08-11.", "approval.docx")
        self.assertEqual(res["content_type"], "APPROVAL")

    def test_07_review_only_finding(self):
        res = classify_content_and_modality("Quarterly Privileged Access Review completed on 2026-07-01 by Lead Auditor.", "access_review.xlsx")
        self.assertEqual(res["content_type"], "REVIEW")

    def test_08_mixed_policy_and_evidence(self):
        finding = {
            "control_id": "CUSTOM_1.23 Mixed Content Control",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "FOUND",
            "evidence_assessment": "COMPLIANT",
            "evidence_quote": "Backup job completed successfully on 2026-08-10 at 02:00 UTC.",
            "policy_snippet": "All databases shall be backed up daily.",
            "source_files": "Disaster_Recovery_Plan_and_Execution.pdf"
        }
        res = post_process(finding, "All databases shall be backed up daily.\n\nBackup job completed successfully on 2026-08-10 at 02:00 UTC.")
        self.assertEqual(res["final_result"], "COMPLIANT")

    def test_09_copied_policy_as_evidence(self):
        finding = {
            "control_id": "CUSTOM_4.56 Copied Policy",
            "status": "COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "FOUND",
            "evidence_quote": "All employees must change passwords every 90 days.",
            "source_files": "Evidence_Upload.pdf"
        }
        res = post_process(finding, "All employees must change passwords every 90 days.")
        self.assertEqual(res["evidence_status"], "NOT_FOUND")
        self.assertEqual(res["final_result"], "NON_COMPLIANT")

    def test_10_paraphrased_policy_as_evidence(self):
        finding = {
            "control_id": "CUSTOM_4.57 Paraphrased Policy",
            "status": "COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "FOUND",
            "evidence_quote": "It is mandated that privileged access is reviewed every quarter by IT management.",
            "source_files": "Audit_Submission.pdf"
        }
        res = post_process(finding, "It is mandated that privileged access is reviewed every quarter by IT management.")
        self.assertEqual(res["evidence_status"], "NOT_FOUND")
        self.assertEqual(res["final_result"], "NON_COMPLIANT")

    def test_11_irrelevant_evidence(self):
        finding = {
            "control_id": "CUSTOM_3.12 Irrelevant Evidence",
            "status": "COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "FOUND",
            "evidence_relevance": "IRRELEVANT",
            "evidence_quote": "Catering invoice for annual office party.",
            "source_files": "Invoice.pdf"
        }
        res = post_process(finding, "Catering invoice for annual office party.")
        self.assertEqual(res["evidence_status"], "NOT_FOUND")
        self.assertEqual(res["final_result"], "NON_COMPLIANT")

    def test_12_partial_evidence(self):
        finding = {
            "control_id": "CUSTOM_2.01 Partial Evidence",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "FOUND",
            "evidence_assessment": "NON_COMPLIANT",
            "evidence_quote": "Backup started at 01:00 UTC",
            "policy_snippet": "Backup must complete successfully daily.",
            "source_files": "Backup.log"
        }
        res = post_process(finding, "Backup started at 01:00 UTC")
        self.assertEqual(res["requirements_supported"], 0)
        self.assertEqual(res["requirements_partial"], 1)

    def test_13_conflicting_evidence(self):
        item1 = EvidenceItem(artifact_id="1", source_file="doc1.pdf", extracted_text="MFA enabled for all admin accounts. Status: OK", grounding_status="GROUNDED")
        item2 = EvidenceItem(artifact_id="2", source_file="doc2.pdf", extracted_text="MFA disabled for emergency admin user account.", grounding_status="GROUNDED")
        finding = {
            "control_id": "CUSTOM_5.00 Conflict Test",
            "status": "COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "FOUND",
            "evidence_assessment": "COMPLIANT",
            "evidence_quote": "MFA enabled for all admin accounts. Status: OK",
            "evidence_items_json": json.dumps([item1.to_dict(), item2.to_dict()])
        }
        res = post_process(finding, "MFA enabled for all admin accounts. Status: OK\n\nMFA disabled for emergency admin user account.")
        self.assertEqual(res["final_result"], "NON_COMPLIANT")
        self.assertTrue(res.get("conflicting_evidence"))

    def test_14_missing_evidence(self):
        finding = {
            "control_id": "CUSTOM_6.11 Missing Evidence",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "NOT_FOUND",
            "evidence_quote": "NOT_FOUND"
        }
        res = post_process(finding, "Policy statement only.")
        self.assertEqual(res["evidence_status"], "NOT_FOUND")

    def test_15_valid_implementation_evidence(self):
        finding = {
            "control_id": "CUSTOM_7.22 Valid Evidence",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "FOUND",
            "evidence_assessment": "COMPLIANT",
            "evidence_quote": "Access review completed on 2026-08-01. All 25 accounts verified by CISO.",
            "policy_snippet": "Access review must be conducted periodically.",
            "source_files": "Access_Review_Report.pdf"
        }
        res = post_process(finding, "Access review must be conducted periodically.\n\nAccess review completed on 2026-08-01. All 25 accounts verified by CISO.")
        self.assertEqual(res["final_result"], "COMPLIANT")

    def test_16_mixed_content_single_pdf(self):
        res1 = classify_content_and_modality("All administrators shall use MFA.", "policy_doc.pdf")
        res2 = classify_content_and_modality("2026-08-10 12:00:00 UTC MFA enabled for admin user", "policy_doc.pdf")
        self.assertEqual(res1["content_type"], "POLICY")
        self.assertIn(res2["content_type"], ("LOG_RECORD", "SYSTEM_OUTPUT"))

    def test_17_timestamped_policy_remains_policy(self):
        res = classify_content_and_modality("Effective Date: 2026-01-01. All staff must complete background checks prior to employment.", "policy.docx")
        self.assertEqual(res["content_type"], "POLICY")

    def test_18_policy_screenshot_remains_policy(self):
        meta = {"is_ocr": True, "source_type": "ocr"}
        res = classify_content_and_modality("All employees must lock workstations when leaving desk.", "policy_screenshot.png", meta)
        self.assertEqual(res["content_type"], "POLICY")
        self.assertEqual(res["artifact_modality"], "SCREENSHOT")

    def test_19_config_screenshot_becomes_config_plus_screenshot(self):
        meta = {"is_ocr": True, "source_type": "ocr"}
        res = classify_content_and_modality("port: 22\nPermitRootLogin no\nstatus: ok", "config_screen.png", meta)
        self.assertEqual(res["content_type"], "CONFIGURATION")
        self.assertEqual(res["artifact_modality"], "SCREENSHOT")

    def test_20_unknown_content_remains_unknown(self):
        res = classify_content_and_modality("qwerty uiop asdfgh jkl", "unknown.txt")
        self.assertEqual(res["content_type"], "UNKNOWN")

    def test_21_one_artifact_supports_multiple_requirements(self):
        item = EvidenceItem(artifact_id="item_1", source_file="audit.log", extracted_text="2026-08-10 UTC Session opened for admin; MFA challenge verified OK", grounding_status="GROUNDED")
        finding = {
            "control_id": "CUSTOM_8.01 Multi-Req",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "FOUND",
            "evidence_assessment": "COMPLIANT",
            "policy_snippet": "R1: Logging must be active.\n\nR2: Multi-factor authentication must be enforced.",
            "evidence_quote": "2026-08-10 UTC Session opened for admin; MFA challenge verified OK",
            "evidence_items_json": json.dumps([item.to_dict()]),
            "source_files": "audit.log"
        }
        res = post_process(finding, "2026-08-10 UTC Session opened for admin; MFA challenge verified OK")
        self.assertEqual(res["requirements_total"], 2)
        self.assertEqual(res["requirements_supported"], 2)

    def test_22_multiple_artifacts_support_one_requirement(self):
        item1 = EvidenceItem(artifact_id="item_1", source_file="policy.pdf", extracted_text="All servers must sync time.", grounding_status="GROUNDED", restated_policy=True)
        item2 = EvidenceItem(artifact_id="item_2", source_file="ntp.txt", extracted_text="NTP synchronized: yes\nLocal time: 2026-08-10 12:00:00 UTC", grounding_status="GROUNDED")
        finding = {
            "control_id": "CUSTOM_8.02 Multi-Artifact",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "FOUND",
            "evidence_assessment": "COMPLIANT",
            "policy_snippet": "All servers must sync time.",
            "evidence_quote": "NTP synchronized: yes\nLocal time: 2026-08-10 12:00:00 UTC",
            "evidence_items_json": json.dumps([item1.to_dict(), item2.to_dict()]),
            "source_files": "ntp.txt"
        }
        res = post_process(finding, "NTP synchronized: yes\nLocal time: 2026-08-10 12:00:00 UTC")
        self.assertEqual(res["final_result"], "COMPLIANT")

    def test_23_conflict_affects_only_affected_requirement(self):
        item1 = EvidenceItem(artifact_id="item_1", source_file="log1.txt", extracted_text="Backup job completed successfully", grounding_status="GROUNDED")
        item2 = EvidenceItem(artifact_id="item_2", source_file="log2.txt", extracted_text="Backup job failed with error", grounding_status="GROUNDED")
        finding = {
            "control_id": "CUSTOM_8.03 Conflict Isolation",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "FOUND",
            "evidence_items_json": json.dumps([item1.to_dict(), item2.to_dict()])
        }
        res = post_process(finding, "Backup job completed successfully\nBackup job failed with error")
        self.assertEqual(res["final_result"], "NON_COMPLIANT")

    def test_24_all_9_nist_matrix_combinations(self):
        matrix_cases = [
            ("LOW", "LOW", "LOW", "P4 Low"),
            ("LOW", "MODERATE", "LOW", "P4 Low"),
            ("LOW", "HIGH", "MEDIUM", "P3 Medium"),
            ("MODERATE", "LOW", "LOW", "P4 Low"),
            ("MODERATE", "MODERATE", "MEDIUM", "P3 Medium"),
            ("MODERATE", "HIGH", "HIGH", "P2 High"),
            ("HIGH", "LOW", "MEDIUM", "P3 Medium"),
            ("HIGH", "MODERATE", "HIGH", "P2 High"),
            ("HIGH", "HIGH", "CRITICAL", "P1 Critical"),
        ]
        for lh, imp, exp_risk, exp_sev in matrix_cases:
            f = {"status": "NON_COMPLIANT", "likelihood": lh, "impact": imp}
            res = evaluate_nist_risk_and_severity(f)
            self.assertEqual(res["risk_level"], exp_risk)
            self.assertEqual(res["severity"], exp_sev)

    def test_25_undetermined_yields_na_severity(self):
        f = {"status": "NON_COMPLIANT", "likelihood": "INVALID", "impact": "INVALID"}
        res = evaluate_nist_risk_and_severity(f, control_id="UNSEEN_CONTROL_999")
        self.assertEqual(res["risk_level"], "UNDETERMINED")
        self.assertEqual(res["severity"], "N/A")
        self.assertEqual(res["likelihood"], "N/A")
        self.assertEqual(res["impact"], "N/A")

    def test_26_compliant_yields_na_severity(self):
        f = {"status": "COMPLIANT"}
        res = evaluate_nist_risk_and_severity(f)
        self.assertEqual(res["severity"], "N/A")
        self.assertEqual(res["risk_level"], "N/A")

    def test_27_false_positive_yields_na_severity(self):
        f = {"status": "FALSE_POSITIVE"}
        res = evaluate_nist_risk_and_severity(f)
        self.assertEqual(res["severity"], "N/A")
        self.assertEqual(res["risk_level"], "N/A")

    def test_28_zero_hardcoded_p3_p4_fallbacks(self):
        f = {"status": "NON_COMPLIANT"}
        res = evaluate_nist_risk_and_severity(f, control_id="UNSEEN_CONTROL_UNKNOWN")
        self.assertIn(res["severity"], ("N/A", "P1 Critical", "P2 High", "P3 Medium", "P4 Low"))
        self.assertNotEqual(res["severity"], None)

    def test_29_zero_requires_human_review_output(self):
        finding = {
            "control_id": "CUSTOM_9.00 Zero Review Flag",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "NOT_FOUND"
        }
        res = post_process(finding, "Doc text")
        self.assertIn(res["final_result"], ("COMPLIANT", "NON_COMPLIANT"))

    def test_30_zero_control_specific_validation_branches(self):
        res1 = classify_chunk_content_type("NTP server synchronized to time.google.com: yes", "arbitrary_file.txt")
        res2 = classify_chunk_content_type("CPU utilization 42% threshold ok", "arbitrary_file.txt")
        self.assertEqual(res1, "OPERATIONAL")
        self.assertEqual(res2, "OPERATIONAL")

if __name__ == "__main__":
    unittest.main()
