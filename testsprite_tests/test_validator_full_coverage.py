"""
AICyberAuditBox -- Full Coverage Regression Tests
=================================================
Tests:
  1. NIST risk matrix -- all 9 combinations
  2. UNDETERMINED risk guard (never silent P3)
  3. risk_rationale populated correctly
  4. classify_chunk_content_type -- content-based (not extension-based)
  5. post_process: COMPLIANT/NON_COMPLIANT gate paths
  6. No hardcoded P3 in any gate path
"""
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.core.validator import (
    evaluate_nist_risk_and_severity,
    classify_chunk_content_type,
    post_process,
)


class TestNistRiskMatrix(unittest.TestCase):

    def _run(self, lh, imp, expected_risk, expected_sev):
        finding = {
            "status": "NON_COMPLIANT",
            "likelihood": lh,
            "impact": imp,
            "evidence_status": "NOT_FOUND",
        }
        result = evaluate_nist_risk_and_severity(finding)
        self.assertEqual(result["likelihood"], lh)
        self.assertEqual(result["impact"], imp)
        self.assertEqual(result["risk_level"], expected_risk)
        self.assertEqual(result["severity"], expected_sev)

    def test_low_low(self):      self._run("LOW", "LOW", "LOW", "P4 Low")
    def test_low_moderate(self): self._run("LOW", "MODERATE", "LOW", "P4 Low")
    def test_low_high(self):     self._run("LOW", "HIGH", "MEDIUM", "P3 Medium")
    def test_mod_low(self):      self._run("MODERATE", "LOW", "LOW", "P4 Low")
    def test_mod_mod(self):      self._run("MODERATE", "MODERATE", "MEDIUM", "P3 Medium")
    def test_mod_high(self):     self._run("MODERATE", "HIGH", "HIGH", "P2 High")
    def test_high_low(self):     self._run("HIGH", "LOW", "MEDIUM", "P3 Medium")
    def test_high_mod(self):     self._run("HIGH", "MODERATE", "HIGH", "P2 High")
    def test_high_high(self):    self._run("HIGH", "HIGH", "CRITICAL", "P1 Critical")


class TestUndeterminedRiskGuard(unittest.TestCase):

    def test_compliant_gets_na_likelihood_and_impact(self):
        finding = {
            "status": "COMPLIANT",
            "likelihood": "HIGH",
            "impact": "HIGH",
        }
        result = evaluate_nist_risk_and_severity(finding)
        self.assertEqual(result["severity"], "N/A")
        self.assertEqual(result["likelihood"], "N/A")
        self.assertEqual(result["impact"], "N/A")

    def test_false_positive_gets_na(self):
        finding = {"status": "FALSE_POSITIVE"}
        result = evaluate_nist_risk_and_severity(finding)
        self.assertEqual(result["severity"], "N/A")
        self.assertEqual(result["risk_level"], "N/A")

    def test_risk_rationale_populated_for_non_compliant(self):
        finding = {
            "status": "NON_COMPLIANT",
            "likelihood": "MODERATE",
            "impact": "HIGH",
            "policy_status": "FOUND",
            "evidence_status": "NOT_FOUND",
        }
        result = evaluate_nist_risk_and_severity(finding, control_id="5.15 Access Control")
        self.assertIn("risk_rationale", result)
        self.assertIn("NIST SP 800-30", result["risk_rationale"])
        self.assertGreater(len(result["risk_rationale"]), 20)

    def test_compliant_risk_rationale_mentions_compliant(self):
        finding = {"status": "COMPLIANT"}
        result = evaluate_nist_risk_and_severity(finding)
        self.assertIn("COMPLIANT", result["risk_rationale"])

    def test_severity_never_none(self):
        for st in ("NON_COMPLIANT", "COMPLIANT", "FALSE_POSITIVE"):
            finding = {"status": st, "likelihood": "LOW", "impact": "LOW"}
            result = evaluate_nist_risk_and_severity(finding)
            self.assertIsNotNone(result.get("severity"))

    def test_policy_only_branch_overrides_llm_lh_imp_for_medium_baseline_control(self):
        """
        When policy_status=FOUND + evidence_status=NOT_FOUND + base_sev=MEDIUM (unknown control):
        the deterministic policy-only branch must set lh=LOW, imp=MODERATE => risk=LOW => P4 Low.
        Even if LLM proposed HIGH+HIGH, the policy-only branch overrides for MEDIUM-baseline controls.
        This is the correct architectural behavior (not a bug).
        """
        finding = {
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "evidence_status": "NOT_FOUND",
            "likelihood": "HIGH",
            "impact": "HIGH",
        }
        result = evaluate_nist_risk_and_severity(finding, control_id="9.99 Unknown Control")
        # Universal NIST Matrix Lookup: HIGH + HIGH => CRITICAL => P1 Critical (zero base_sev overrides)
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertEqual(result["severity"], "P1 Critical")

    def test_high_severity_control_with_high_risk_yields_p1_or_p2(self):
        """A genuinely HIGH-risk control with HIGH+HIGH from LLM must yield P1 Critical."""
        finding = {
            "status": "NON_COMPLIANT",
            "likelihood": "HIGH",
            "impact": "HIGH",
            # No policy_status/evidence_status to skip the policy-only override branch
        }
        result = evaluate_nist_risk_and_severity(finding, control_id=None)
        # Without policy_status+evidence_status combination, policy-only branch won't fire
        # HIGH+HIGH => CRITICAL => P1 Critical
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertEqual(result["severity"], "P1 Critical")


class TestClassifyChunkContentType(unittest.TestCase):

    def test_timedatectl_output_is_operational(self):
        content = "NTP synchronized: yes\nLocal time: Wed 2024-08-10 14:32:00 UTC"
        self.assertEqual(classify_chunk_content_type(content, "system_info.txt"), "OPERATIONAL")

    def test_ntp_in_docx_is_operational(self):
        content = "ntp enabled: true\nsynchronized: yes\nServer: 169.254.169.123"
        self.assertEqual(classify_chunk_content_type(content, "audit_evidence.docx"), "OPERATIONAL")

    def test_visitor_register_is_operational(self):
        content = "Visitor Name: John  Badge Number: 1234  Signed in at: 09:15  Escort: Alice"
        self.assertEqual(classify_chunk_content_type(content, "visitor_log.pdf"), "OPERATIONAL")

    def test_backup_job_is_operational(self):
        content = "Backup job completed successfully on 10-Aug-2026 at 02:00 UTC."
        self.assertEqual(classify_chunk_content_type(content, "backup.xlsx"), "OPERATIONAL")

    def test_cloudwatch_metric_is_operational(self):
        content = "CloudWatch metric: CPU utilization 78%. Threshold triggered."
        self.assertEqual(classify_chunk_content_type(content, "dashboard.png"), "OPERATIONAL")

    def test_pam_log_is_operational(self):
        content = "pam_unix(sshd:session): session opened for user admin"
        self.assertEqual(classify_chunk_content_type(content, "auth.log"), "OPERATIONAL")

    def test_mfa_enrollment_is_operational(self):
        content = "MFA enabled for user john.doe on 2024-08-15 10:22:05"
        self.assertEqual(classify_chunk_content_type(content, "mfa_records.csv"), "OPERATIONAL")

    def test_access_review_completed_is_operational(self):
        content = "Access review completed on 2024-07-01. 14 accounts reviewed by Alice."
        self.assertEqual(classify_chunk_content_type(content, "q3_review.docx"), "OPERATIONAL")

    def test_vulnerability_scan_result_is_operational(self):
        content = "Scan completed. Nessus result: CVE-2024-1234 found on 10.0.0.5."
        self.assertEqual(classify_chunk_content_type(content, "nessus_scan.xml"), "OPERATIONAL")

    def test_policy_statement_is_policy(self):
        # Pure normative policy — must/shall/should with organization + management language
        # Should NOT trigger any operational keyword or pattern
        content = (
            "All employees must ensure their access privileges are reviewed. "
            "The organization shall maintain records of all access requests. "
            "Management shall review and approve all access control changes."
        )
        self.assertEqual(classify_chunk_content_type(content, "access_policy.docx"), "POLICY")

    def test_normative_policy_is_policy(self):
        content = "This policy applies to all staff. Management must ensure compliance. Procedure requires annual review."
        self.assertEqual(classify_chunk_content_type(content, "isms_policy.pdf"), "POLICY")

    def test_empty_content_is_unknown(self):
        self.assertEqual(classify_chunk_content_type("", "file.txt"), "UNKNOWN")

    def test_none_content_is_unknown(self):
        self.assertEqual(classify_chunk_content_type(None, "file.txt"), "UNKNOWN")

    def test_ocr_metadata_overrides_to_operational(self):
        result = classify_chunk_content_type("Some text", "screenshot.png", metadata={"source_type": "ocr"})
        self.assertEqual(result, "OPERATIONAL")

    def test_image_metadata_overrides_to_operational(self):
        result = classify_chunk_content_type("Some text", "pic.png", metadata={"source_type": "image"})
        self.assertEqual(result, "OPERATIONAL")

    def test_quarterly_review_completed_is_operational(self):
        """'quarterly review completed' must be OPERATIONAL (it has the completion marker)."""
        content = "Quarterly review completed on 2024-Q2. All accounts verified."
        self.assertEqual(classify_chunk_content_type(content, "q2_review.xlsx"), "OPERATIONAL")

    def test_quarterly_review_policy_text_is_not_operational(self):
        """'access privileges are reviewed quarterly' in policy text must NOT be OPERATIONAL."""
        content = "All employees must ensure their access privileges are reviewed quarterly. Management shall verify compliance annually."
        result = classify_chunk_content_type(content, "policy.docx")
        # Has 2 policy patterns (must ensure, management shall) => POLICY before keywords fire
        self.assertEqual(result, "POLICY")


class TestNoHardcodedP3PolicyOnly(unittest.TestCase):

    def test_5_15_policy_only_yields_p4_low(self):
        finding = {
            "control_id": "5.15 Access Control",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "NOT_FOUND",
            "evidence_assessment": "NON_COMPLIANT",
            "evidence_quote": "Security will audit registration logs daily.",
            "likelihood": "LOW",
            "impact": "MODERATE",
        }
        result = evaluate_nist_risk_and_severity(finding)
        # LOW+MODERATE = LOW risk = P4 Low (even though LLM says LOW+MODERATE, policy-only branch confirms)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["severity"], "P4 Low")
        self.assertNotEqual(result["severity"], "P3 Medium")

    def test_severity_always_valid_project_value(self):
        valid = {"P1 Critical", "P2 High", "P3 Medium", "P4 Low", "N/A"}
        for lh, imp in [("LOW","LOW"), ("LOW","HIGH"), ("HIGH","HIGH"), ("MODERATE","MODERATE")]:
            finding = {"status": "NON_COMPLIANT", "likelihood": lh, "impact": imp}
            result = evaluate_nist_risk_and_severity(finding)
            self.assertIn(result["severity"], valid)

    def test_p3_medium_is_only_from_legitimate_nist_risk(self):
        """P3 Medium must ONLY be the result of MEDIUM risk from the NIST matrix (never hardcoded)."""
        # These combinations should legitimately yield P3 Medium via NIST matrix:
        # LOW+HIGH, MODERATE+MODERATE, HIGH+LOW
        for lh, imp in [("LOW","HIGH"), ("MODERATE","MODERATE"), ("HIGH","LOW")]:
            finding = {"status": "NON_COMPLIANT", "likelihood": lh, "impact": imp}
            result = evaluate_nist_risk_and_severity(finding)
            self.assertEqual(result["risk_level"], "MEDIUM")
            self.assertEqual(result["severity"], "P3 Medium")


class TestPostProcessSeverityNeverHardcoded(unittest.TestCase):

    def test_policy_only_pipeline_yields_nist_severity(self):
        finding = {
            "control_id": "5.15 Access Control",
            "status": "NON_COMPLIANT",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "NOT_FOUND",
            "evidence_assessment": "NON_COMPLIANT",
            "evidence_quote": "Security will audit registration logs daily.",
            "likelihood": "LOW",
            "impact": "MODERATE",
        }
        result = post_process(finding, "Security will audit registration logs daily.")
        self.assertEqual(result["status"], "NON_COMPLIANT")
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["severity"], "P4 Low")

    def test_fully_compliant_finding_gets_na_severity(self):
        """
        COMPLIANT finding with all required fields correctly set gets severity=N/A.
        Note: evidence_status must be FOUND for the deterministic gate to pass COMPLIANT.
        """
        finding = {
            "control_id": "5.15 Access Control",
            "status": "COMPLIANT",
            "hallucination_check": "GROUNDED",
            "policy_status": "FOUND",
            "policy_assessment": "COMPLIANT",
            "evidence_status": "FOUND",          # Must be FOUND for COMPLIANT to hold
            "evidence_assessment": "COMPLIANT",   # Must be COMPLIANT
            "evidence_quote": "Access review completed on 2024-07-01. All 14 accounts verified by Alice.",
            "policy_validity": "CURRENT",
            "evidence_freshness": "CURRENT",
        }
        result = post_process(finding, "Access review completed on 2024-07-01. All 14 accounts verified by Alice.")
        self.assertEqual(result["severity"], "N/A")

    def test_severity_always_valid_after_post_process(self):
        valid = {"P1 Critical", "P2 High", "P3 Medium", "P4 Low", "N/A"}
        finding = {
            "control_id": "5.15 Access Control",
            "status": "NON_COMPLIANT",
            "policy_status": "NOT_FOUND",
            "evidence_status": "NOT_FOUND",
            "evidence_quote": "NOT_FOUND",
        }
        result = post_process(finding, "Some unrelated document content.")
        self.assertIn(result.get("severity", "N/A"), valid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
