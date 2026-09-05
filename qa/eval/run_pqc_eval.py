# -*- coding: utf-8 -*-
"""
PQC (Post-Quantum Cryptography Readiness) Module Eval Harness

Distinct from qa/eval/run_golden_eval.py (which evaluates the LLM-driven RAG
pipeline against a labeled dataset and needs the full local LLM/DB stack
running). The PQC scanner is 100% deterministic (src/core/parsers/pqc_parser.py)
-- zero LLM involvement -- so this harness needs no external services at all.
It runs a table of hand-authored input strings through PQCParser().parse()
and asserts the exact fields the parser is documented to produce: algorithm
classification, severity, context enrichment (CA/Key/Protocol/exposure/port/
environment), risk scoring, business priority, OEM matching, dependency
mapping, and control routing -- plus a grounding check that every finding's
evidence is a real, unmodified substring of its input.

Usage (no LLM/DB/Docker required):
    python qa\\eval\\run_pqc_eval.py
"""

import os
import sys

sys.path.insert(0, os.getcwd())

from src.core.parsers.pqc_parser import PQCParser


# ══════════════════════════════════════════════════════════════════════════════
# TEST HARNESS
# ══════════════════════════════════════════════════════════════════════════════

_PASS = 0
_FAIL = 0
_FAILURES = []


def check(case_id, description, condition, detail=""):
    global _PASS, _FAIL
    if condition:
        _PASS += 1
    else:
        _FAIL += 1
        _FAILURES.append(f"[{case_id}] {description}" + (f" -- {detail}" if detail else ""))


def find_one(findings, title_contains):
    """Returns the first finding whose title contains the given substring
    (case-insensitive), or None."""
    for f in findings:
        if title_contains.lower() in (f.title or "").lower():
            return f
    return None


def parse(filename, content):
    actionable, info = PQCParser().parse(filename, content)
    return actionable + info


# ══════════════════════════════════════════════════════════════════════════════
# A. ALGORITHM DETECTION -- one row per class, table-driven
# ══════════════════════════════════════════════════════════════════════════════

def eval_algorithm_detection():
    cases = [
        # (case_id, filename, content, title_substr, expected_quantum_status, expected_severity_in)
        ("A1", "evidence.txt", "Certificate : RSA2048", "RSA2048", "VULNERABLE", ("CRITICAL",)),
        ("A2", "evidence.txt", "Certificate : RSA4096", "RSA4096", "VULNERABLE", ("HIGH",)),
        ("A3", "evidence.txt", "Signature Algorithm : DSA", "DSA", "VULNERABLE", ("CRITICAL",)),
        ("A4", "evidence.txt", "Key Exchange : DH Group 14", "Diffie-Hellman Group 14", "VULNERABLE", ("CRITICAL",)),
        ("A5", "evidence.txt", "Key Exchange : DH Group 16", "Diffie-Hellman Group 16", "VULNERABLE", ("HIGH",)),
        ("A6", "evidence.txt", "Curve : P-256", "P-256", "VULNERABLE", ("HIGH",)),
        ("A7", "evidence.txt", "Signature : Ed25519", "Ed25519", "VULNERABLE", ("HIGH",)),
        ("A8", "evidence.txt", "Hash : MD5", "MD5", "WEAK", ("HIGH",)),
        ("A9", "evidence.txt", "Hash : SHA1", "SHA-1", "WEAK", ("HIGH",)),
        ("A10", "evidence.txt", "Cipher : 3DES", "3DES", "WEAK", ("CRITICAL",)),
        ("A11", "evidence.txt", "Cipher : RC4", "RC4", "WEAK", ("CRITICAL",)),
        ("A12", "evidence.txt", "Protocol : SSLv3", "SSLv3", "WEAK", ("CRITICAL",)),
        ("A13", "evidence.txt", "Protocol : TLS 1.0", "TLS 1.0", "WEAK", ("CRITICAL",)),
        ("A14", "evidence.txt", "Mode : CBC", "CBC-mode", "WEAK", ("MEDIUM",)),
        ("A15", "evidence.txt", "Cipher : AES256-GCM", "AES-256-GCM", "SAFE", ("INFO",)),
        ("A16", "evidence.txt", "Hash : SHA384", "SHA-384", "SAFE", ("INFO",)),
        ("A17", "evidence.txt", "KEM : CRYSTALS-Kyber", "CRYSTALS-Kyber", "SAFE", ("INFO",)),
        ("A18", "evidence.txt", "Signature : CRYSTALS-Dilithium", "CRYSTALS-Dilithium", "SAFE", ("INFO",)),
        ("A19", "evidence.txt", "Signature : SPHINCS+", "SPHINCS+", "SAFE", ("INFO",)),
        ("A20", "evidence.txt", "Signature : Falcon", "Falcon", "SAFE", ("INFO",)),
        ("A21", "evidence.txt", "AEAD : ChaCha20-Poly1305", "ChaCha20-Poly1305", "SAFE", ("INFO",)),
    ]
    for case_id, fname, content, title_sub, exp_qs, exp_sev in cases:
        findings = parse(fname, content)
        f = find_one(findings, title_sub)
        check(case_id, f"detects '{title_sub}'", f is not None, f"no finding matched title containing '{title_sub}'")
        if f:
            check(case_id, f"'{title_sub}' quantum_status == {exp_qs}", f.quantum_status == exp_qs,
                  f"got {f.quantum_status}")
            check(case_id, f"'{title_sub}' severity in {exp_sev}", f.severity in exp_sev,
                  f"got {f.severity}")


# ══════════════════════════════════════════════════════════════════════════════
# B. GROUNDING -- every finding's evidence must be a real substring of the input
# ══════════════════════════════════════════════════════════════════════════════

def eval_grounding():
    content = (
        "Palo Alto Firewall - External DMZ Segment\n"
        "Production Environment\n"
        "IPSec VPN Profile (Port: 500)\n"
        "-----------------------------\n"
        "Encryption : AES256\n"
        "Authentication : SHA1\n"
        "Key Exchange : DH Group 14\n"
        "Certificate : RSA2048\n"
    )
    findings = parse("paloalto_ipsec_prod.txt", content)
    check("B1", "at least one finding produced for grounding check", len(findings) > 0)
    for f in findings:
        check("B1", f"evidence for '{f.title}' is a real substring of input",
              f.evidence in content, f"evidence={f.evidence!r} not found verbatim in input")


# ══════════════════════════════════════════════════════════════════════════════
# C. FALSE-POSITIVE GUARD -- can_parse() must require 2+ signal keywords
# ══════════════════════════════════════════════════════════════════════════════

def eval_false_positive_guard():
    unrelated = (
        "Employee Leave Policy\n"
        "All staff must submit leave requests via the HR portal at least 5 "
        "working days in advance. Encryption of personal leave records is "
        "handled by the HR system automatically.\n"
    )
    can_parse = PQCParser().can_parse("hr_policy.txt", unrelated)
    check("C1", "single stray 'encryption' mention does NOT trigger PQC parsing",
          can_parse is False, f"can_parse returned {can_parse}, expected False")

    real_config = "TLS Configuration\nCertificate : RSA2048\nCipher Suite : AES256\n"
    can_parse2 = PQCParser().can_parse("config.txt", real_config)
    check("C2", "genuine multi-signal config DOES trigger PQC parsing",
          can_parse2 is True, f"can_parse returned {can_parse2}, expected True")


# ══════════════════════════════════════════════════════════════════════════════
# D. CONTEXT ENRICHMENT -- CA/Key/Protocol split, exposure, environment, port
# ══════════════════════════════════════════════════════════════════════════════

def eval_context_enrichment():
    content = (
        "Palo Alto Firewall - External DMZ Segment\n"
        "Production Environment\n"
        "IPSec VPN Profile (Port: 500)\n"
        "-----------------------------\n"
        "Encryption : AES256\n"
        "Authentication : SHA1\n"
        "Key Exchange : DH Group 14\n"
        "Certificate : RSA2048\n"
    )
    findings = parse("paloalto_ipsec_prod.txt", content)

    rsa = find_one(findings, "RSA2048")
    check("D1", "RSA2048 finding classified into ca_algorithm (from 'Certificate:' label)",
          rsa is not None and rsa.ca_algorithm == "RSA2048", f"ca_algorithm={rsa.ca_algorithm if rsa else None!r}")

    dh = find_one(findings, "Diffie-Hellman Group 14")
    check("D2", "DH Group 14 finding classified into key_algorithm (from 'Key Exchange:' label)",
          dh is not None and dh.key_algorithm != "", f"key_algorithm={dh.key_algorithm if dh else None!r}")

    check("D3", "port extracted as '500' from 'Port: 500' label",
          rsa is not None and rsa.port == "500", f"port={rsa.port if rsa else None!r}")
    check("D4", "environment tagged PROD from 'Production Environment' line",
          rsa is not None and rsa.environment == "PROD", f"environment={rsa.environment if rsa else None!r}")
    check("D5", "exposure tagged EXTERNAL from 'External DMZ' line",
          rsa is not None and rsa.exposure_context == "EXTERNAL", f"exposure_context={rsa.exposure_context if rsa else None!r}")

    # Regression: word-boundary fix -- "Load Balancer" must NOT false-match the
    # bare "lan" substring inside "baLANcer" and suppress a genuine EXTERNAL signal.
    lb_content = "External-facing web tier\nLoad Balancer Configuration\nCertificate : RSA2048\n"
    lb_findings = parse("lb_config.txt", lb_content)
    lb_rsa = find_one(lb_findings, "RSA2048")
    check("D6", "REGRESSION: 'Load Balancer' text does not false-trigger INTERNAL via 'lan' substring",
          lb_rsa is not None and lb_rsa.exposure_context == "EXTERNAL",
          f"exposure_context={lb_rsa.exposure_context if lb_rsa else None!r} (bug would show '' or INTERNAL)")

    # Regression: word-boundary environment check -- "product" must not match "prod".
    prod_word_content = "Product Catalog Service\nCertificate : RSA2048\n"
    pw_findings = parse("product_catalog.txt", prod_word_content)
    pw_rsa = find_one(pw_findings, "RSA2048")
    check("D7", "REGRESSION: 'Product Catalog' does not false-trigger PROD via bare 'prod' substring",
          pw_rsa is not None and pw_rsa.environment != "PROD",
          f"environment={pw_rsa.environment if pw_rsa else None!r} (bug would show PROD)")

    # No-fabrication check: no port/environment/exposure signal present anywhere.
    bare_content = "Certificate : RSA2048\n"
    bare_findings = parse("bare.txt", bare_content)
    bare_rsa = find_one(bare_findings, "RSA2048")
    check("D8", "no port fabricated when absent from evidence",
          bare_rsa is not None and bare_rsa.port == "", f"port={bare_rsa.port if bare_rsa else None!r}")
    check("D9", "no environment fabricated when absent from evidence",
          bare_rsa is not None and bare_rsa.environment == "", f"environment={bare_rsa.environment if bare_rsa else None!r}")


# ══════════════════════════════════════════════════════════════════════════════
# E. RISK SCORING -- worked examples + SAFE-never-scored rule
# ══════════════════════════════════════════════════════════════════════════════

def eval_risk_scoring():
    banking_content = (
        "Internet Banking App - External Production System\n"
        "Palo Alto PAN-OS Firewall Configuration\n"
        "IPSec VPN Profile\n"
        "-----------------------------\n"
        "Certificate : RSA2048\n"
    )
    findings = parse("banking_arch.txt", banking_content)
    rsa = find_one(findings, "RSA2048")
    check("E1", "Internet Banking / external / RSA2048 scores exactly 96",
          rsa is not None and rsa.risk_score == 96, f"risk_score={rsa.risk_score if rsa else None!r}")
    check("E2", "risk_band == CRITICAL for score 96",
          rsa is not None and rsa.risk_band == "CRITICAL", f"risk_band={rsa.risk_band if rsa else None!r}")

    hr_content = "Internal HR Portal\nEmployee Records System\nAuthentication : SHA1\n"
    hr_findings = parse("hr_portal.txt", hr_content)
    hr_sha1 = find_one(hr_findings, "SHA-1")
    check("E3", "Internal HR / SHA-1 (WEAK) produces a risk_score",
          hr_sha1 is not None and hr_sha1.risk_score is not None, "risk_score was None")
    check("E4", "Internal HR / SHA-1 bands to MEDIUM (~52, matching the RFP worked example)",
          hr_sha1 is not None and hr_sha1.risk_band == "MEDIUM",
          f"risk_score={hr_sha1.risk_score if hr_sha1 else None!r} risk_band={hr_sha1.risk_band if hr_sha1 else None!r}")

    # SAFE algorithms must NEVER get a risk_score, even on a critical asset.
    safe_content = "Internet Banking App - External Production System\nEncryption : AES256\n"
    safe_findings = parse("banking_safe.txt", safe_content)
    aes = find_one(safe_findings, "AES-256")
    check("E5", "SAFE finding on a CRITICAL asset gets NO risk_score (not a misleading high number)",
          aes is not None and aes.risk_score is None, f"risk_score={aes.risk_score if aes else None!r}")


# ══════════════════════════════════════════════════════════════════════════════
# F. BUSINESS PRIORITY CLASSIFICATION -- one case per bucket
# ══════════════════════════════════════════════════════════════════════════════

def eval_business_priority():
    cases = [
        ("F1", "Internet Banking App", "Certificate : RSA2048", "CRITICAL"),
        ("F2", "Core Banking Database", "Certificate : RSA2048", "CRITICAL"),
        ("F3", "API Gateway Service", "Certificate : RSA2048", "HIGH"),
        ("F4", "Internal HR Portal", "Certificate : RSA2048", "MEDIUM"),
        ("F5", "Archive Backup System", "Certificate : RSA2048", "LOW"),
    ]
    for case_id, heading, line, expected_bucket in cases:
        content = f"{heading}\n{line}\n"
        findings = parse(f"{case_id.lower()}.txt", content)
        f = find_one(findings, "RSA2048")
        check(case_id, f"'{heading}' classified as business_priority={expected_bucket}",
              f is not None and f.business_priority == expected_bucket,
              f"got {f.business_priority if f else None!r}")


# ══════════════════════════════════════════════════════════════════════════════
# G. OEM READINESS MATCHING
# ══════════════════════════════════════════════════════════════════════════════

def eval_oem_matching():
    cases = [
        ("G1", "Palo Alto PAN-OS Firewall\nCertificate : RSA2048\n", "Palo Alto PAN-OS"),
        ("G2", "Thales Luna HSM Key Configuration\nCertificate : RSA2048\n", "Thales Luna HSM"),
        ("G3", "Oracle TDE Encryption Settings\nCertificate : RSA2048\n", "Oracle TDE"),
    ]
    for case_id, content, expected_product in cases:
        findings = parse(f"{case_id.lower()}.txt", content)
        f = find_one(findings, "RSA2048")
        check(case_id, f"OEM product matched as '{expected_product}'",
              f is not None and f.oem_product == expected_product,
              f"got {f.oem_product if f else None!r}")
        if f:
            check(case_id, f"OEM readiness status populated for '{expected_product}'",
                  bool(f.oem_readiness_status), "oem_readiness_status was blank")

    # No-fabrication: unrecognized vendor must leave OEM fields blank.
    unknown_content = "Generic Router Configuration\nCertificate : RSA2048\n"
    uf = find_one(parse("g4.txt", unknown_content), "RSA2048")
    check("G4", "unrecognized vendor leaves oem_product blank (never fabricated)",
          uf is not None and uf.oem_product == "", f"oem_product={uf.oem_product if uf else None!r}")


# ══════════════════════════════════════════════════════════════════════════════
# H. DEPENDENCY MAPPING
# ══════════════════════════════════════════════════════════════════════════════

def eval_dependency_mapping():
    content = (
        "Architecture Dependency Map:\n"
        "Internet Banking App -> Load Balancer -> Firewall -> VPN Gateway -> Oracle DB\n\n"
        "Internet Banking App - External Production System\n"
        "Certificate : RSA2048\n\n"
        "Oracle DB - Production Database\n"
        "Certificate : RSA2048\n"
    )
    findings = parse("banking_arch_dep.txt", content)
    vulnerable = [f for f in findings if f.quantum_status == "VULNERABLE"]
    check("H1", "both chain-listed vulnerable assets produced findings", len(vulnerable) >= 2,
          f"only {len(vulnerable)} VULNERABLE findings")
    flagged = [f for f in vulnerable if f.migration_dependency_flag]
    check("H2", "at least one finding flagged migration_dependency_flag=True (chain has 2+ vulnerable nodes)",
          len(flagged) >= 1, "no finding had migration_dependency_flag=True")
    for f in flagged:
        check("H2", f"'{f.asset_name}' dependency_chain is non-empty when flagged",
              bool(f.dependency_chain), "dependency_chain was blank on a flagged finding")

    # No-fabrication: a file with no dependency-chain text must never set the flag.
    no_chain_content = "Standalone Server\nCertificate : RSA2048\n"
    nc = find_one(parse("h3.txt", no_chain_content), "RSA2048")
    check("H3", "no chain text in evidence -> migration_dependency_flag stays False",
          nc is not None and nc.migration_dependency_flag is False,
          f"migration_dependency_flag={nc.migration_dependency_flag if nc else None!r}")
    check("H3", "no chain text in evidence -> dependency_chain stays blank",
          nc is not None and nc.dependency_chain == "",
          f"dependency_chain={nc.dependency_chain if nc else None!r}")


# ══════════════════════════════════════════════════════════════════════════════
# I. CONTROL ROUTING -- PQC-1..PQC-9 keyword buckets
# ══════════════════════════════════════════════════════════════════════════════

def eval_control_routing():
    cases = [
        ("I1", "sshd_config.txt", "SSH Server Configuration\nHostKeyAlgorithm : RSA2048\n", "PQC-3"),
        ("I2", "ipsec_vpn.txt", "IPSec Phase 2 Proposal\nCertificate : RSA2048\n", "PQC-4"),
        ("I3", "certificate_export.txt", "Certificate Authority Export\nSignature Algorithm : RSA2048\n", "PQC-5"),
        ("I4", "oracle_tde_config.txt", "TDE Encryption Settings\nAlgorithm : RSA2048\n", "PQC-6"),
        ("I5", "openssl_library_versions.txt", "OpenSSL Library Version 1.0.2\nCipher : RC4\n", "PQC-7"),
        ("I6", "hsm_key_config.txt", "HSM Key Configuration\nAlgorithm : RSA2048\n", "PQC-8"),
        ("I7", "firmware_signing.txt", "Firmware Signing Key\nAlgorithm : RSA2048\n", "PQC-9"),
        ("I8", "tls_config.txt", "TLS Server Configuration\nCertificate : RSA2048\n", "PQC-5"),  # 'certificate' still wins over generic TLS bucket
        ("I9", "generic_scan.txt", "Weak Cipher : RC4\n", "PQC-1"),
    ]
    for case_id, fname, content, expected_control in cases:
        findings = parse(fname, content)
        f = findings[0] if findings else None
        check(case_id, f"'{fname}' routes to {expected_control}",
              f is not None and f.control_id == expected_control,
              f"got {f.control_id if f else None!r} for content {content!r}")


# ══════════════════════════════════════════════════════════════════════════════
# J. REGRESSION -- exact snippets used throughout prior verification passes
# ══════════════════════════════════════════════════════════════════════════════

def eval_regression():
    content = "TLS Configuration\nCertificate: RSA2048\nKey Exchange: DH Group 14\nAuthentication: SHA1\nCipher: AES256-GCM"
    findings = parse("test.txt", content)
    expected = {
        "RSA2048": ("CRITICAL", "VULNERABLE"),
        "Diffie-Hellman Group 14": ("CRITICAL", "VULNERABLE"),
        "SHA-1": ("HIGH", "WEAK"),
        "AES-256-GCM": ("INFO", "SAFE"),
    }
    for title_sub, (exp_sev, exp_qs) in expected.items():
        f = find_one(findings, title_sub)
        check("J1", f"REGRESSION base case: '{title_sub}' severity/status unchanged",
              f is not None and f.severity == exp_sev and f.quantum_status == exp_qs,
              f"got severity={f.severity if f else None!r} quantum_status={f.quantum_status if f else None!r}")


# ══════════════════════════════════════════════════════════════════════════════
# RUN ALL
# ══════════════════════════════════════════════════════════════════════════════

def main():
    suites = [
        ("A. Algorithm detection", eval_algorithm_detection),
        ("B. Grounding", eval_grounding),
        ("C. False-positive guard", eval_false_positive_guard),
        ("D. Context enrichment", eval_context_enrichment),
        ("E. Risk scoring", eval_risk_scoring),
        ("F. Business priority", eval_business_priority),
        ("G. OEM readiness matching", eval_oem_matching),
        ("H. Dependency mapping", eval_dependency_mapping),
        ("I. Control routing", eval_control_routing),
        ("J. Regression (base cases)", eval_regression),
    ]

    print("=" * 78)
    print("PQC MODULE EVAL SUITE -- 100% offline, no LLM/DB/Docker required")
    print("=" * 78)

    for name, fn in suites:
        before = _PASS + _FAIL
        fn()
        after = _PASS + _FAIL
        suite_fail = sum(1 for msg in _FAILURES if True) - 0  # recomputed below
        print(f"  {name:<32} ran {after - before} assertions")

    print("-" * 78)
    total = _PASS + _FAIL
    print(f"RESULT: {_PASS}/{total} assertions passed ({_FAIL} failed)")
    if _FAILURES:
        print("\nFAILURES:")
        for msg in _FAILURES:
            print(f"  - {msg}")
    print("=" * 78)

    return 0 if _FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
