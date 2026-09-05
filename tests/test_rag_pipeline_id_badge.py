# -*- coding: utf-8 -*-
"""
Executes the FULL LIVE RAG PIPELINE on 'ID Badge and Facility Access Policy V17.0.pdf'
targeting ISO 27001:2022 Control 5.15 Access Control and Control 7.2 Physical Entry.
Uses LangGraph, Smart Vector Chunking, Gemma 4 e4b, and deterministic validator gates.
"""

import os
import sys
import io
import time

sys.path.append(os.getcwd())

os.environ["RESOURCE_GUARD_CRITICAL_PERCENT"] = "2"
os.environ["RESOURCE_GUARD_CRITICAL_FLOOR_GB"] = "0.2"
os.environ["LLM_BACKEND"] = "llama.cpp"
os.environ["OLLAMA_HOST"] = "http://127.0.0.1:11434"
os.environ["EMBEDDING_HOST"] = "http://127.0.0.1:11435"

from src.core.parsers.doc_parsers import extract_text
from src.core.bg_worker import generate_ollama_findings
from src.core.controls_data import USE_CASES
from src.db.database import SessionLocal, force_master, AuditReport

print("=" * 80)
print("RUNNING LIVE RAG PIPELINE ON 'ID Badge and Facility Access Policy V17.0.pdf'")
print("=" * 80)

pdf_path = r"c:\Users\HP\Desktop\audit test_box\samples\AICyberAuditOPS Sample Data\ID Badge and Facility Access Policy V17.0.pdf"
fname = "ID Badge and Facility Access Policy V17.0.pdf"

if not os.path.exists(pdf_path):
    print(f"[-] Error: File not found at {pdf_path}")
    sys.exit(1)

with open(pdf_path, "rb") as f:
    b = f.read()

f_obj = io.BytesIO(b)
f_obj.name = fname
extracted_text = extract_text(f_obj)
print(f"[+] Successfully extracted {len(extracted_text)} characters from {fname}")

file_registry = {fname: extracted_text}
full_context_str = f"--- Document: {fname} ---\n{extracted_text}\n"

# Select exact indices for 5.15 Access Control (14) and 7.2 Physical Entry (46)
selected_sls = [14, 46]
print(f"[+] Targeting exact Controls: 5.15 Access Control (Index 14) and 7.2 Physical Entry (Index 46)")

# Create live session in database
session_id = f"test_id_badge_{int(time.time())}"
with force_master():
    db = SessionLocal()
    report = AuditReport(
        session_id=session_id,
        session_title="ID Badge Audit Verification Session",
        created_by="test_lead_auditor@organization.com",
        framework="ISO/IEC 27001:2022",
        status="In Progress"
    )
    db.add(report)
    db.commit()
    report_id = report.id
    db.close()

print(f"[+] Initialized live session {session_id} in database")
print(f"\n[+] Launching live LangGraph RAG pipeline with Gemma 4 e4b...")

start_t = time.time()
res = generate_ollama_findings(
    context=full_context_str,
    file_names_list=list(file_registry.keys()),
    selected_sls=selected_sls,
    model_choice="Gemma 4 (e4b)",
    bg_key=session_id,
    checkpoint_session_id=session_id,
    audit_mode="Deep",
    file_registry=file_registry,
    username="Test Lead Auditor"
)

elapsed = time.time() - start_t
print(f"\n[+] generate_ollama_findings() completed in {elapsed:.2f}s")

if len(res) == 4:
    resolved_list, findings, all_results, _ = res
else:
    resolved_list, findings, all_results = res

print("\n" + "=" * 80)
print("LIVE RAG PIPELINE RESULTS FOR ID BADGE POLICY PDF:")
print("=" * 80)

for f in findings:
    cid = f.get("control_id") or f.get("control") or "Unknown"
    status = f.get("status") or "UNKNOWN"
    pol_st = f.get("policy_status") or "N/A"
    pol_ass = f.get("policy_assessment") or "N/A"
    ev_st = f.get("evidence_status") or "N/A"
    ev_ass = f.get("evidence_assessment") or "N/A"
    quote = f.get("evidence_quote") or f.get("evidence_snippet") or "None"
    finding_text = f.get("finding") or f.get("reasoning") or "N/A"
    rec = f.get("recommendation") or "N/A"
    
    print(f"\n[CONTROL] {cid}")
    print(f"  • Final Status       : {status}")
    print(f"  • Policy Side        : Status={pol_st} | Assessment={pol_ass}")
    print(f"  • Evidence Side      : Status={ev_st} | Assessment={ev_ass}")
    print(f"  • Extracted Quote    : {quote}")
    print(f"  • Finding / Reasoning: {finding_text}")
    print(f"  • Recommendation     : {rec}")

print("\n" + "=" * 80)
