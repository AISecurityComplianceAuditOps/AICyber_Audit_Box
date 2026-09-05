# -*- coding: utf-8 -*-
"""
Direct Evaluation for ISO 27001 Control 5.15 (Access Control)
on 'ID Badge and Facility Access Policy V17.0.pdf' with Gemma 4 e4b.
"""

import os
import sys
import io
import time

sys.path.append(os.getcwd())

from src.core.parsers.doc_parsers import extract_text
from src.ai.audit_chains import GENERATOR_PROMPT_TEMPLATE, NativeOllamaChain
from src.core.validator import post_process
from src.core.controls_data import USE_CASES

pdf_path = r"c:\Users\HP\Desktop\audit test_box\samples\AICyberAuditOPS Sample Data\ID Badge and Facility Access Policy V17.0.pdf"
fname = "ID Badge and Facility Access Policy V17.0.pdf"

with open(pdf_path, "rb") as f:
    b = f.read()

f_obj = io.BytesIO(b)
f_obj.name = fname
extracted_text = extract_text(f_obj)

use_case_515 = next((uc for uc in USE_CASES if str(uc.get("use_case", "")).startswith("5.15")), None)
control_id = use_case_515["use_case"]
control_name = use_case_515["label"]
expected_evidence = use_case_515.get("expected", "Access Control Policy, badge/keycard authorization rules, user privilege restrictions")

chain = NativeOllamaChain(model_name="gemma4:e4b", prompt_template=GENERATOR_PROMPT_TEMPLATE)

input_dict = {
    "summary_text": f"Document '{fname}' contains comprehensive ID Badge and Facility Access Control policies, RFID card access rules, visitor management procedures, and access de-provisioning workflows.",
    "condensed_context": f"--- DOCUMENT: {fname} ---\n{extracted_text[:12000]}",
    "control_id": control_id,
    "control_label": control_name,
    "expected_evidence": expected_evidence,
    "feedback_section": "",
    "standard": "ISO/IEC 27001:2022"
}

print(f"[+] Querying Gemma 4 e4b for {control_id} with extracted text ({len(extracted_text)} chars)...")
start_t = time.time()
schema_res = chain.invoke(input_dict)
elapsed = time.time() - start_t
print(f"[+] LLM Response received in {elapsed:.2f}s")

parsed = schema_res.dict() if hasattr(schema_res, "dict") else dict(schema_res)
parsed["control_id"] = control_id
parsed["control_name"] = control_name

print("\n" + "=" * 75)
print("RAW LLM OUTPUT (Gemma 4 e4b):")
print("=" * 75)
print(f"  • Policy Status    : {parsed.get('policy_status')}")
print(f"  • Policy Assessment: {parsed.get('policy_assessment')}")
print(f"  • Policy Name      : {parsed.get('policy_name')}")
print(f"  • Policy Version   : {parsed.get('policy_version')}")
print(f"  • Policy Clause    : {parsed.get('policy_clause')}")
print(f"  • Policy Gap       : {parsed.get('policy_gap')}")
print(f"  • Evidence Status  : {parsed.get('evidence_status')}")
print(f"  • Evidence Assess  : {parsed.get('evidence_assessment')}")
print(f"  • Evidence Relevance: {parsed.get('evidence_relevance')}")
print(f"  • Evidence Quote   : {parsed.get('evidence_quote')}")
print(f"  • Evidence Gap     : {parsed.get('evidence_gap')}")
print(f"  • Raw Status       : {parsed.get('status')}")

# Run post_process deterministic validator gates
validated = post_process(parsed, extracted_text, {"5.15": [expected_evidence]})

print("\n" + "=" * 75)
print("DETERMINISTIC VALIDATOR RESULTS (validator.py):")
print("=" * 75)
print(f"  • Final Status     : {validated.get('status')}")
print(f"  • Final Result     : {validated.get('final_result')}")
print(f"  • Policy Status    : {validated.get('policy_status')}")
print(f"  • Evidence Status  : {validated.get('evidence_status')}")
print(f"  • Grounding Check  : {validated.get('hallucination_check')}")
print(f"  • Evidence Snippet : {validated.get('evidence_snippet')}")
print(f"  • Severity         : {validated.get('severity')}")
print(f"  • Recommendation   : {validated.get('recommendation')}")
print("=" * 75)
