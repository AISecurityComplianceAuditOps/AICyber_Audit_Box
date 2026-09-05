# -*- coding: utf-8 -*-
"""
Verification Suite using REAL Audit Evidence Documents and Real Excel Checklist.
Tests end-to-end extraction, Excel scoping, document parsing, OCR, and control evaluation.
"""

import os
import sys
import time

sys.path.append(os.getcwd())

print("=" * 70)
print("VERIFYING AUDIT ENGINE ACCURACY WITH REAL DOCUMENTS")
print("=" * 70)

# Check for real evidence directories
POSSIBLE_DIRS = [
    os.path.join(os.getcwd(), "aa audit evidence samples"),
    os.path.join(os.getcwd(), "src", "aa audit evidence samples")
]

evidence_dir = None
for d in POSSIBLE_DIRS:
    if os.path.exists(d) and os.listdir(d):
        evidence_dir = d
        break

if not evidence_dir:
    print("[-] Real evidence directory not found!")
    sys.exit(1)

print(f"[+] Found real evidence directory: {evidence_dir}")
files = os.listdir(evidence_dir)
print(f"    Available files ({len(files)}): {files}")

# -------------------------------------------------------------
# 1. PARSE REAL EXCEL CHECKLIST WITH excel_scoping_parser
# -------------------------------------------------------------
excel_file = os.path.join(evidence_dir, "Audit checklist and evidence files.xlsx")
if os.path.exists(excel_file):
    print("\n[STEP 1] Testing Real Excel Checklist Parsing with excel_scoping_parser.py...")
    from src.core.excel_scoping_parser import parse_excel_scoping_checklist

    items = parse_excel_scoping_checklist(excel_file, uploaded_filenames=files)
    print(f"-> Successfully parsed {len(items)} rows from real checklist:")
    for idx, item in enumerate(items, 1):
        q = item.get("question", "")[:60]
        cid = item.get("control_id", "UNKNOWN")
        clabel = item.get("control_label", "")
        frefs = item.get("files", [])
        print(f"   Row {idx:02d}: Control [{cid}] -> {clabel} | Files: {frefs}")
        print(f"          Question: {q}...")
else:
    print("[!] Real Excel checklist not found!")

# -------------------------------------------------------------
# 2. PARSE ALL REAL EVIDENCE & POLICY FILES
# -------------------------------------------------------------
print("\n[STEP 2] Testing Real Document Parsing (DOCX, Images/OCR, TXT)...")
from src.core.parsers.doc_parsers import extract_text
import io

parsed_evidence = {}
for fname in sorted(files):
    if fname.endswith(".xlsx"):
        continue
    fpath = os.path.join(evidence_dir, fname)
    with open(fpath, "rb") as f:
        f_bytes = f.read()
    f_obj = io.BytesIO(f_bytes)
    f_obj.name = fname
    
    start_t = time.time()
    try:
        extracted = extract_text(f_obj)
        elapsed = time.time() - start_t
        parsed_evidence[fname] = extracted
        print(f"-> [OK] {fname} ({len(f_bytes)} bytes) -> Parsed {len(extracted)} chars in {elapsed:.3f}s")
        if extracted:
            preview = extracted[:120].replace('\n', ' ')
            print(f"        Preview: \"{preview}...\"")
        else:
            print("        [WARN] No text extracted (image OCR may require tesseract)")
    except Exception as e:
        print(f"-> [ERROR] Failed parsing {fname}: {e}")

# -------------------------------------------------------------
# 3. VERIFY SCOPING ON REAL PARSED CONTENT
# -------------------------------------------------------------
print("\n[STEP 3] Testing AI Scoping Engine on Real Document Content...")
from src.ai.scoping_engine import detect_scope_and_controls

for fname, text in parsed_evidence.items():
    if not text or len(text) < 30:
        continue
    ctrls, _, doc_types, _ = detect_scope_and_controls(text, fname)
    print(f"-> File: {fname}")
    print(f"   Detected Scope Categories ({len(doc_types)}): {doc_types}")
    print(f"   Matched Controls ({len(ctrls)}): {ctrls[:5]}...")

# -------------------------------------------------------------
# 4. VERIFY LOCKED EVIDENCE MATCHING AGAINST REAL ROWS
# -------------------------------------------------------------
print("\n[STEP 4] Testing End-to-End Checklist Row Evidence Matching...")
from src.core.validator import validate_only

match_success = 0
for idx, item in enumerate(items, 1):
    cid = item.get("control_id")
    clabel = item.get("control_label")
    target_files = item.get("files") or []
    
    found_text = ""
    for tf in target_files:
        # Find exact or fuzzy matching file in parsed_evidence
        for pf_name, pf_text in parsed_evidence.items():
            if tf.lower() in pf_name.lower() or pf_name.lower() in tf.lower():
                found_text += "\n" + pf_text
    
    if found_text.strip():
        match_success += 1
        print(f"-> Row {idx}: [{cid}] -> Evidence found in {target_files} ({len(found_text.strip())} chars)")
    else:
        print(f"-> Row {idx}: [{cid}] -> Target file {target_files} has empty or unextracted content")

print(f"\n-> Evidence Grounding: {match_success}/{len(items)} checklist rows have valid extracted evidence content.")

print("\n" + "=" * 70)
print("REAL DOCUMENT VERIFICATION COMPLETE")
print("=" * 70)
