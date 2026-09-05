# -*- coding: utf-8 -*-
"""
Verification script for VAPT control evaluation with LLM backend.
Tests whether selecting a VAPT control correctly routes through
VAPT_GENERATOR_PROMPT_TEMPLATE and uses Gemma 4 e4b.
"""

import os
import sys
import time

sys.path.append(os.getcwd())

from src.ai.audit_chains import GENERATOR_PROMPT_TEMPLATE, NativeOllamaChain
from src.core.validator import post_process

sample_nmap_scan = """
Nmap scan report for 192.168.1.105 (db-prod.internal)
Host is up (0.0024s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p1 Ubuntu 4ubuntu2.8 (vulnerable to CVE-2024-6387 regreSSHion)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
3306/tcp open  mysql   MySQL 5.7.20 (Insecure: unencrypted transport allowed, TLS v1.0 enabled)
6379/tcp open  redis   Redis key-value store 5.0.7 (Unauthenticated: no password set, protected-mode disabled)
"""

# Test VAPT-1 External Perimeter / VAPT-5 Database
control_id = "VAPT-5 Database Injection & SQLi Hardening"
control_label = "Database Injection & Insecure Configuration (VAPT-5)"
expected_evidence = "Database port exposure (3306, 5432), weak TLS configurations, default unauthenticated database access"

chain = NativeOllamaChain(model_name="gemma4:e4b", prompt_template=GENERATOR_PROMPT_TEMPLATE)

input_dict = {
    "summary_text": "Sample infrastructure penetration testing and network service vulnerability scan report.",
    "condensed_context": f"--- SCAN LOG: nmap_internal_scan.txt ---\n{sample_nmap_scan}",
    "control_id": control_id,
    "control_label": control_label,
    "expected_evidence": expected_evidence,
    "feedback_section": "",
    "standard": "VAPT Framework"
}

print("=" * 75)
print("TESTING VAPT CONTROL EVALUATION WITH LLM (Gemma 4 e4b)")
print("=" * 75)
print(f"[*] Control: {control_id}")
print(f"[*] Standard: VAPT Framework")
print(f"[*] Sending sample Nmap scan log with open MySQL (3306) and Redis (6379)...")

start_t = time.time()
schema_res = chain.invoke(input_dict)
elapsed = time.time() - start_t
print(f"[+] LLM Response generated in {elapsed:.2f}s")

parsed = schema_res.dict() if hasattr(schema_res, "dict") else dict(schema_res)
parsed["control_id"] = control_id
parsed["control_name"] = control_label

print("\n" + "-" * 75)
print("LLM VAPT OUTPUT:")
print("-" * 75)
print(f"  • Status          : {parsed.get('status')}")
print(f"  • Severity        : {parsed.get('severity')}")
print(f"  • Severity Score  : {parsed.get('severity_score')} (CVSS)")
print(f"  • Justification   : {parsed.get('justification')}")
print(f"  • Recommendation  : {parsed.get('recommendation')}")
print(f"  • Evidence Items  : {parsed.get('evidence') or parsed.get('evidence_items')}")

# Run post-processing
validated = post_process(parsed, sample_nmap_scan, {"VAPT-5": [expected_evidence]})

print("\n" + "-" * 75)
print("VALIDATOR RESULT:")
print("-" * 75)
print(f"  • Final Status    : {validated.get('status')}")
print(f"  • Final Result    : {validated.get('final_result')}")
print(f"  • Grounding Check : {validated.get('hallucination_check')}")
print(f"  • Severity        : {validated.get('severity')}")
print("=" * 75)
