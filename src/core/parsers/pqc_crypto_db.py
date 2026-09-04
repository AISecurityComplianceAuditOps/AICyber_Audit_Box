# -*- coding: utf-8 -*-
"""
pqc_crypto_db.py -- Offline Cryptographic Algorithm Registry for PQC Fast Parser.

Loads three databases from JSON knowledge files (src/core/knowledge/):
  1. pqc_x509_oids.json         -- X.509 OID to algorithm map (NIST/ITU-T, 53 OIDs)
  2. iana_tls_ciphersuites.json -- IANA TLS Cipher Suite registry, 356 suites (from
                                   official IANA CSV tls-parameters-4.csv)
  3. liboqs_algorithms.json     -- Open Quantum Safe liboqs algorithm catalogue,
                                   49 algorithms (NIST Finals + Round 4 + OQS experiments)

Public API (used by pqc_parser.py):
    scan_oids_in_text(text)       -> list[(oid_str, meta_dict)]
    scan_iana_hex_in_text(text)   -> list[(hex_str, meta_dict)]
    scan_liboqs_in_text(text)     -> list[(keyword, meta_dict)]

    lookup_oid(oid)               -> dict | None
    lookup_iana_hex(hex_code)     -> dict | None
    lookup_liboqs_algo(keyword)   -> dict | None

Sources:
  - IANA:   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
  - NIST:   FIPS 203/204/205, NIST IR 8413, RFC 8032/8422, NIST SP 800-131A Rev 2
  - liboqs: https://openquantumsafe.org/liboqs/algorithms/
  - CWE:    https://cwe.mitre.org/data/definitions/1240.html
"""
from __future__ import annotations
import json
import os
import re as _re
from typing import Optional

# ============================================================================
# LOAD JSON KNOWLEDGE FILES
# ============================================================================

def _load_json(filename: str) -> dict:
    """Load a JSON knowledge file from src/core/knowledge/. Falls back to {} on error."""
    # Walk up from this file's location to find src/core/knowledge/
    base = os.path.dirname(os.path.abspath(__file__))           # src/core/parsers/
    knowledge_dir = os.path.join(base, "..", "knowledge")       # src/core/knowledge/
    path = os.path.normpath(os.path.join(knowledge_dir, filename))
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        print(f"[pqc_crypto_db] WARNING: Could not load '{filename}': {exc}", flush=True)
        return {}


# X.509 OID registry (53 OIDs: RSA, DSA, DH, ECC, ML-KEM, ML-DSA, SLH-DSA, Falcon)
X509_OID_DB: dict = _load_json("pqc_x509_oids.json")

# IANA TLS Cipher Suite registry (356 suites from official IANA CSV)
IANA_CIPHER_DB: dict = _load_json("iana_tls_ciphersuites.json")

# liboqs algorithm catalogue (49 algorithms: NIST Finals + Round 4 + OQS experiments)
LIBOQS_ALGO_DB: dict = _load_json("liboqs_algorithms.json")

# CWE / NIST compliance mappings (informational, used in reports)
CWE_NIST_DB: dict = _load_json("cwe_nist_mappings.json")

# ============================================================================
# COMPILED REGEX PATTERNS (auto-built from loaded databases)
# ============================================================================

# OID regex -- matches dotted-decimal OID strings in text
def _build_oid_pattern(db: dict) -> "_re.Pattern":
    oids = [oid for oid in db if "." in str(oid)]
    if not oids:
        return _re.compile(r'(?!)')  # never-match fallback
    return _re.compile(
        r'\b(' + '|'.join(_re.escape(o) for o in sorted(oids, key=len, reverse=True)) + r')\b'
    )


# IANA hex -- matches 0xNN,0xNN  or  0xNNNN  patterns in TLS logs/pcaps/OpenSSL output
_IANA_HEX_PATTERN = _re.compile(
    r'(?:0[xX]([0-9A-Fa-f]{2})[,\s]+0[xX]([0-9A-Fa-f]{2})'  # 0x13,0x01
    r'|0[xX]([0-9A-Fa-f]{4}))',                                # 0x1301
    _re.IGNORECASE,
)

# liboqs keyword regex -- word-boundary matched to avoid false positives
def _build_liboqs_pattern(db: dict) -> "_re.Pattern":
    if not db:
        return _re.compile(r'(?!)')
    # Sort longest first so e.g. "falcon-512" matches before "falcon"
    keys = sorted(db.keys(), key=len, reverse=True)
    return _re.compile(
        r'\b(' + '|'.join(_re.escape(k) for k in keys) + r')\b',
        _re.IGNORECASE,
    )


_OID_PATTERN = _build_oid_pattern(X509_OID_DB)
_LIBOQS_PATTERN = _build_liboqs_pattern(LIBOQS_ALGO_DB)


# ============================================================================
# PUBLIC LOOKUP FUNCTIONS
# ============================================================================

def lookup_oid(oid_str: str) -> Optional[dict]:
    """Return OID metadata dict or None if not in X509_OID_DB."""
    return X509_OID_DB.get(oid_str.strip())


def lookup_iana_hex(hex_code: str) -> Optional[dict]:
    """
    Return IANA cipher suite metadata dict or None.
    Accepts: '0035', '00,35', '0x00,0x35', '0x0035' -- normalizes to 4-char uppercase.
    """
    code = hex_code.upper().replace("0X", "").replace(",", "").replace(" ", "")
    if len(code) == 2:
        code = "00" + code
    return IANA_CIPHER_DB.get(code[:4])


def lookup_liboqs_algo(keyword: str) -> Optional[dict]:
    """Return liboqs algorithm metadata dict or None (case-insensitive)."""
    return LIBOQS_ALGO_DB.get(keyword.lower().strip())


def lookup_cwe(cwe_id: str) -> Optional[dict]:
    """Return CWE/NIST compliance mapping dict or None (e.g. 'CWE-1240')."""
    return CWE_NIST_DB.get(cwe_id.strip())


# ============================================================================
# PUBLIC SCAN FUNCTIONS (used by pqc_parser.py)
# ============================================================================

def scan_oids_in_text(text: str) -> list:
    """
    Scan raw text for X.509 OID strings.
    Returns list of (oid_str, metadata_dict) tuples, deduped by OID.
    """
    seen: set = set()
    results = []
    for m in _OID_PATTERN.finditer(text):
        oid = m.group(1)
        if oid not in seen:
            seen.add(oid)
            meta = X509_OID_DB.get(oid)
            if meta:
                results.append((oid, meta))
    return results


def scan_iana_hex_in_text(text: str) -> list:
    """
    Scan raw text for IANA TLS cipher suite hex codes.
    Returns list of (hex_code_str, metadata_dict) tuples, deduped by code.
    """
    seen: set = set()
    results = []
    for m in _IANA_HEX_PATTERN.finditer(text):
        if m.group(1) and m.group(2):
            code = (m.group(1) + m.group(2)).upper()
        elif m.group(3):
            code = m.group(3).upper()
        else:
            continue
        if code not in seen:
            seen.add(code)
            meta = IANA_CIPHER_DB.get(code)
            if meta:
                results.append((code, meta))
    return results


def scan_liboqs_in_text(text: str) -> list:
    """
    Scan raw text for liboqs/OQS algorithm keywords.
    Returns list of (keyword_str, metadata_dict) tuples, deduped by keyword.
    """
    seen: set = set()
    results = []
    for m in _LIBOQS_PATTERN.finditer(text):
        kw = m.group(1).lower()
        if kw not in seen:
            seen.add(kw)
            meta = LIBOQS_ALGO_DB.get(kw)
            if meta:
                results.append((kw, meta))
    return results
