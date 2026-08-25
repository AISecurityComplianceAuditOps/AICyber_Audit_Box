# -*- coding: utf-8 -*-
"""
VAPT parser regression suite. Unlike tests/run_evals.py (ISO RAG pipeline),
this is fully deterministic -- no LLM/DB server needed -- so it runs in seconds.

Covers:
  - Real sample scanner files (Nmap console text, a real Nessus-shaped HTML
    export with content past the can_parse() sampling window) run through the
    actual parse_tool_file() dispatcher.
  - Image screenshots must never be claimed by a scanner parser (OCR fast-path).
  - Real screenshot -> OCR -> finding-synthesis path (BurpParser/NmapParser on
    OCR'd text), matching bg_worker.py's fast-technical-mode behavior.
  - Targeted regression checks for 3 parser fixes made 2026-08-24: BurpParser's
    Informational-severity guard, NessusParser's 2-of-3 weak-signal threshold,
    and TrivyParser's actionable/info severity split.

Run: python tests/test_vapt_parsers.py
"""
import sys
import os
import io
import json
import time

sys.path.append(os.getcwd())

from src.core.parsers import parse_tool_file, ALL_PARSERS, is_image_file
from src.core.parsers.burp_parser import BurpParser
from src.core.parsers.nessus_parser import NessusParser
from src.core.parsers.trivy_parser import TrivyParser

SAMPLES_DIR = os.path.join("aa audit evidence samples", "test_vapt samples")

results = []


def check(label, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    results.append((status, label, detail))
    print(f"[{status}] {label}" + (f" -- {detail}" if detail and status == "FAIL" else ""))


def run_real_sample_tests():
    print("\n--- Real sample files ---")

    # Nmap: real console scan output
    path = os.path.join(SAMPLES_DIR, "raw_nmap_vulnerability_scan_console.txt")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        findings, extra = parse_tool_file("raw_nmap_vulnerability_scan_console.txt", content)
        check("Nmap real console output produces findings", len(findings) > 0, f"got {len(findings)}")
        check("Nmap dispatch returns an AssetInventory as extra", extra is not None and extra.__class__.__name__ == "AssetInventory")
    else:
        print(f"[SKIP] Nmap sample not found at {path}")

    # Nessus-shaped HTML: real export where content starts well past the first
    # 100K chars (a large embedded stylesheet pushes it out) -- verifies the
    # dispatcher still correctly extracts findings via the Stage 3 fallback even
    # when Stage 2's can_parse() sampling window misses the signal.
    path = os.path.join(SAMPLES_DIR, "NOCPL_vu0k9r.html")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        findings, extra = parse_tool_file("NOCPL_vu0k9r.html", content)
        check("Real Nessus-shaped HTML export produces findings", len(findings) > 0, f"got {len(findings)}")
        # This file's actual signal content starts at character ~160,000 (a large
        # embedded <style> block precedes it) -- confirms can_parse() itself now
        # correctly claims it via Stage 2 of the dispatcher, not just Stage 3's
        # NessusParser-as-fallback safety net (which would mask a regression here).
        claimed_by = [p.__class__.__name__ for p in ALL_PARSERS if p.can_parse("NOCPL_vu0k9r.html", content)]
        check("NessusParser.can_parse() itself claims this file (not just the Stage 3 fallback)",
              "NessusParser" in claimed_by, f"claimed by: {claimed_by}")
    else:
        print(f"[SKIP] NOCPL sample not found at {path}")

    # Screenshots must never be claimed by a scanner parser (image fast-path)
    for img_name in ["shot_burp_sqli.png", "shot_burp_xss.png", "shot_nmap_scan.png"]:
        check(f"Image fast-path: {img_name} is recognized as an image", is_image_file(img_name))
        findings, extra = parse_tool_file(img_name, "placeholder -- should never be read for an image")
        check(f"Image fast-path: {img_name} returns no parser findings", findings == [] and extra is None)


def run_ocr_screenshot_tests():
    print("\n--- Real screenshots via OCR -> VAPT finding synthesis (slow: OCR) ---")
    try:
        from src.core.parsers.doc_parsers import extract_text
    except Exception as e:
        print(f"[SKIP] Could not import extract_text (OCR deps unavailable?): {e}")
        return

    for img_name in ["shot_burp_sqli.png", "shot_burp_xss.png", "shot_nmap_scan.png"]:
        path = os.path.join(SAMPLES_DIR, img_name)
        if not os.path.exists(path):
            print(f"[SKIP] {img_name} not found")
            continue
        with open(path, "rb") as f:
            raw_bytes = f.read()
        buf = io.BytesIO(raw_bytes)
        buf.name = img_name
        t0 = time.time()
        ocr_text = extract_text(buf) or ""
        elapsed = time.time() - t0
        check(f"OCR extracts usable text from {img_name}", len(ocr_text.strip()) > 10, f"{len(ocr_text)} chars in {elapsed:.1f}s")
        if ocr_text.strip():
            actionable, info = parse_tool_file("ocr_" + img_name + ".txt", ocr_text)
            check(f"OCR'd {img_name} synthesizes at least one finding", len(actionable) > 0, f"got {len(actionable)}")


def run_burp_severity_regression():
    print("\n--- BurpParser: Informational severity must not be overridden by title keyword ---")
    bp = BurpParser()
    score, _ = bp._calculate_score_and_vector("Cross-site scripting (reflected) - low risk sample", "Information", "Firm")
    check("Informational + 'scripting' in title -> score stays 0.0 (not force-elevated)", score == 0.0, f"got {score}")
    score2, _ = bp._calculate_score_and_vector("Cross-site scripting (reflected)", "High", "Certain")
    check("High + 'scripting' in title -> still gets the specific XSS CVSS score (7.2)", score2 == 7.2, f"got {score2}")


def run_nessus_threshold_regression():
    print("\n--- NessusParser: can_parse() requires 2-of-3 weak phrases, not 1 ---")
    np_ = NessusParser()
    single_phrase_doc = "This is an ordinary ISO 27001 risk assessment document. Please review the risk factor for asset criticality."
    check(
        "A document with only ONE weak phrase ('risk factor') is NOT claimed as Nessus",
        not np_.can_parse("risk_register.txt", single_phrase_doc)
    )
    two_phrase_doc = "Scan summary: risk factor High. See plugin output below for full details of the vulnerability."
    check(
        "A document with TWO weak phrases together IS claimed as Nessus",
        np_.can_parse("scan_summary.txt", two_phrase_doc)
    )
    structural_doc = "<NessusClientData_v2><Report></Report></NessusClientData_v2>"
    check(
        "A document with the structural XML tag is claimed alone (no phrase needed)",
        np_.can_parse("native.nessus", structural_doc)
    )


def run_trivy_split_regression():
    print("\n--- TrivyParser: actionable vs informational severity split ---")
    tp = TrivyParser()
    trivy_sample = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "sample-image:latest",
        "Results": [{
            "Target": "sample-image:latest (debian 11)",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2023-0001", "PkgName": "openssl", "InstalledVersion": "1.1.1",
                 "FixedVersion": "1.1.2", "Title": "OpenSSL buffer overflow", "Severity": "HIGH"},
                {"VulnerabilityID": "CVE-2023-0002", "PkgName": "curl", "InstalledVersion": "7.60",
                 "FixedVersion": "", "Title": "Informational curl notice", "Severity": "UNKNOWN"},
            ]
        }]
    })
    check("can_parse() recognizes a real Trivy JSON shape", tp.can_parse("trivy_scan.json", trivy_sample))
    actionable, info = tp.parse("trivy_scan.json", trivy_sample)
    check("Exactly 1 actionable finding (the HIGH one)", len(actionable) == 1, f"got {len(actionable)}")
    check("Exactly 1 informational finding (the UNKNOWN one)", len(info) == 1, f"got {len(info)}")


if __name__ == "__main__":
    run_real_sample_tests()
    run_burp_severity_regression()
    run_nessus_threshold_regression()
    run_trivy_split_regression()
    run_ocr_screenshot_tests()  # slowest (real OCR) -- runs last

    total = len(results)
    passed = sum(1 for s, _, _ in results if s == "PASS")
    print(f"\n{'='*70}\n{passed}/{total} checks passed\n{'='*70}")
    sys.exit(0 if passed == total else 1)
