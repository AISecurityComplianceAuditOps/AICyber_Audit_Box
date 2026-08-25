# -*- coding: utf-8 -*-
"""
Audit Models Module
Defines the Pydantic schemas used for structured LLM outputs and validation rules.
"""

from pydantic import BaseModel, Field, model_validator
from typing import Literal, List, Optional

class EvidenceItem(BaseModel):
    """
    Pydantic schema representing a single cited evidence item.
    """
    source: str = Field(description="Document Name")
    page: str = Field(description="Page Number")
    excerpt: str = Field(description="Supporting evidence text")

class AuditFindingSchema(BaseModel):
    """
    Pydantic schema representing a structured compliance audit finding.
    Determines compliance status based solely on documented evidence and control coverage.
    """
    status: Literal["COMPLIANT", "NON_COMPLIANT", "FALSE_POSITIVE"] = Field(
        description="The compliance status of the control based on the evidence."
    )
    severity: Literal["N/A", "Low", "Medium", "High", "Critical"] = Field(
        description="The severity level of the finding."
    )
    evidence_strength: Literal["Strong", "Moderate", "Weak", "None", "STRONG", "MODERATE", "WEAK", "NONE"] = Field(
        description="Strength of the documented evidence."
    )
    control_coverage: int = Field(
        ge=0,
        le=100,
        description="Estimated percentage of control requirements covered (0-100)."
    )
    evidence_count: int = Field(
        ge=0,
        description="Count of distinct evidence items cited."
    )
    business_impact: str = Field(
        default="",
        description="Potential impact of the identified gaps."
    )
    remediation_priority: Literal["Low", "Medium", "High", "Immediate"] = Field(
        description="Remediation priority for addressing gaps."
    )
    justification: str = Field(
        description="Detailed auditor explanation supported by evidence."
    )
    missing_requirements: List[str] = Field(
        default=[],
        description="Key requirements missing (required for NON_COMPLIANT, empty for COMPLIANT)."
    )
    recommendation: str = Field(
        default="",
        description="Specific remediation actions."
    )
    evidence: List[EvidenceItem] = Field(
        default=[],
        description="List of supporting evidence items."
    )
    policy_present: Literal["Yes", "No", "Partial", "YES", "NO", "PARTIAL", "Found", "FOUND", "Not Found", "NOT FOUND", "Compliant", "COMPLIANT"] = Field(
        default="No",
        description="Is a documented policy present for this control?"
    )
    evidence_present: Literal["Yes", "No", "Partial", "YES", "NO", "PARTIAL", "Found", "FOUND", "Not Found", "NOT FOUND", "Compliant", "COMPLIANT"] = Field(
        default="No",
        description="Is implementation evidence present for this control?"
    )
    severity_score: float = Field(
        default=0.0,
        description="Vulnerability score from 0.0 to 10.0"
    )

    # ── Policy vs Evidence split (RAG accuracy overhaul, Phase 5) ──────────────
    # These are the new, precise parallel fields alongside the legacy
    # policy_present/evidence_present above. Kept unvalidated here on purpose --
    # clean_and_normalize_data() in audit_chains.py normalizes raw LLM output into
    # this fixed vocabulary before the schema is ever constructed, and Phase 6's
    # deterministic post_process() (not a Pydantic validator) is what actually
    # enforces consistency and computes final_result -- this schema just carries
    # whatever the LLM/normalizer produced.
    policy_status: Literal["FOUND", "NOT_FOUND"] = Field(
        default="NOT_FOUND",
        description="Was a relevant policy/procedure/requirement located at all?"
    )
    policy_assessment: Literal["COMPLIANT", "NON_COMPLIANT"] = Field(
        default="NON_COMPLIANT",
        description="Does the located policy actually satisfy the control's specific requirement?"
    )
    policy_name: str = Field(default="", description="Name/title of the policy document, if found.")
    policy_version: str = Field(default="", description="Policy version/revision, if stated.")
    policy_clause: str = Field(default="", description="Specific clause/section of the policy relied on.")
    policy_effective_date: str = Field(default="", description="Policy effective date, if stated.")
    policy_review_date: str = Field(default="", description="Policy last-review date, if stated.")
    policy_expiry_date: str = Field(default="", description="Policy expiry date, if stated.")
    policy_validity: Literal["CURRENT", "EXPIRED", "REVIEW_OVERDUE", "UNKNOWN"] = Field(
        default="UNKNOWN",
        description="Never inferred/assumed -- UNKNOWN unless the document states dates/review frequency."
    )
    policy_finding: str = Field(default="", description="What was found regarding the policy.")
    policy_gap: str = Field(default="No policy gap identified.", description="The specific policy deficiency, or 'No policy gap identified.'")

    evidence_status: Literal["FOUND", "NOT_FOUND"] = Field(
        default="NOT_FOUND",
        description="Was implementation evidence (not just a policy statement) located at all?"
    )
    evidence_assessment: Literal["COMPLIANT", "NON_COMPLIANT"] = Field(
        default="NON_COMPLIANT",
        description="Does the located evidence actually demonstrate the control operating?"
    )
    evidence_file: str = Field(default="", description="Source filename the evidence came from.")
    evidence_location: str = Field(default="", description="Page/section/row/slide the evidence came from.")
    evidence_type: str = Field(default="", description="Kind of evidence, e.g. screenshot, log, report.")
    evidence_date: str = Field(default="", description="Date/timestamp on the evidence itself, if present.")
    evidence_freshness: Literal["CURRENT", "STALE", "EXPIRED", "UNKNOWN"] = Field(
        default="UNKNOWN",
        description="Never a fixed 30/60/90-day rule -- UNKNOWN unless freshness can actually be determined."
    )
    evidence_finding: str = Field(default="", description="What was found regarding the evidence.")
    evidence_gap: str = Field(default="No evidence gap identified.", description="The specific evidence deficiency, or 'No evidence gap identified.'")
    evidence_relevance: Literal["DIRECT", "PARTIAL", "RELATED", "IRRELEVANT"] = Field(
        default="IRRELEVANT",
        description="DIRECT includes equivalent/alternative implementations satisfying the objective in different "
                    "terminology -- not literal keyword matching. RELATED = same topic, doesn't prove the control."
    )

    final_result: Literal["COMPLIANT", "NON_COMPLIANT"] = Field(
        default="NON_COMPLIANT",
        description="The LLM's own attempt at the deterministic AND-formula result. Phase 6 recomputes and "
                     "overrides this in Python rather than trusting it as-is -- carried here for now as the "
                     "field the prompt asks for."
    )
    final_reason: str = Field(default="", description="Human-readable explanation of the final result.")

    @model_validator(mode='after')
    def enforce_compliance_rule_consistency(self) -> 'AuditFindingSchema':
        """
        Enforces strict compliance auditing consistency rules:
        1. If status is COMPLIANT or FALSE_POSITIVE, severity must be N/A.
        2. If status is COMPLIANT, at least one valid evidence quote must be present.
        3. If status is NON_COMPLIANT, severity cannot be N/A.
        4. Map severity based on severity_score if status is NON_COMPLIANT.
        """
        status_val = self.status
        severity_val = self.severity
        evidence_list = self.evidence or []

        # Rule 1: Compliant / False Positive rules
        if status_val in ("COMPLIANT", "FALSE_POSITIVE"):
            if severity_val != "N/A":
                object.__setattr__(self, 'severity', 'N/A')
            if status_val == "COMPLIANT":
                if not evidence_list:
                    raise ValueError("Compliance status cannot be set to 'COMPLIANT' if no evidence is found.")
                # Ensure at least one evidence has a valid quote
                has_valid_quote = any(e.excerpt and e.excerpt.strip() != "NOT_FOUND" for e in evidence_list)
                if not has_valid_quote:
                    raise ValueError("Compliance status cannot be set to 'COMPLIANT' if no verbatim evidence quote was found in the evidence excerpts.")

        # Rule 2: Gaps rules (Non-Compliant)
        elif status_val == "NON_COMPLIANT":
            # Map severity according to user's defined ranges, respecting explicit severity label
            sev_input = str(self.severity or "").strip().capitalize()
            score = self.severity_score

            if "Critical" in sev_input or "Crit" in sev_input:
                if score < 9.0:
                    score = 9.5
                mapped_sev = "Critical"
            elif "High" in sev_input or "P2" in sev_input:
                if score < 7.0 or score >= 9.0:
                    score = 8.5
                mapped_sev = "High"
            elif "Medium" in sev_input or "Med" in sev_input or "P3" in sev_input:
                if score < 4.0 or score >= 7.0:
                    score = 5.5
                mapped_sev = "Medium"
            elif "Low" in sev_input or "P4" in sev_input:
                if score < 0.1 or score >= 4.0:
                    score = 2.0
                mapped_sev = "Low"
            else:
                # Default to score-based mapping
                mapped_sev = "Medium"
                if score >= 9.0:
                    mapped_sev = "Critical"
                elif score >= 7.0:
                    mapped_sev = "High"
                elif score >= 4.0:
                    mapped_sev = "Medium"
                elif score >= 0.1:
                    mapped_sev = "Low"
                else:
                    score = 5.5
                    mapped_sev = "Medium"

            object.__setattr__(self, 'severity_score', score)
            object.__setattr__(self, 'severity', mapped_sev)


            if not self.business_impact or self.business_impact.strip() in ("", "NOT_FOUND"):
                object.__setattr__(self, 'business_impact', 'Potential security exposure or compliance gap due to missing controls.')
            if not self.recommendation or self.recommendation.strip() in ("", "NOT_FOUND"):
                object.__setattr__(self, 'recommendation', 'Establish and implement documented procedures to satisfy the control requirements.')

        return self
