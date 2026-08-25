# -*- coding: utf-8 -*-
"""
Deterministic Post-Quantum Cryptography (PQC) Readiness scanner.

Scans uploaded evidence text -- TLS/SSL, SSH, IPSec/VPN, PKI/certificate, database
encryption-at-rest, HSM/KMS, or code-signing configuration exports/dumps (plain
text, HTML/XML, or PDF-extracted text; any filename) -- for known cryptographic
algorithm strings and classifies each hit as:
  - "VULNERABLE": broken by Shor's algorithm on a sufficiently large quantum
    computer (RSA, DSA, Diffie-Hellman/DHE, ECC/ECDSA/ECDH).
  - "WEAK": classically weak/deprecated, not PQC-specific but still flagged
    (MD5, SHA-1, DES/3DES/RC4, SSLv2/SSLv3/TLS1.0/TLS1.1, CBC-mode).
  - "SAFE": quantum-resistant / NIST-selected PQC (AES-256, SHA-256+, SHA-3,
    CRYSTALS-Kyber/ML-KEM, CRYSTALS-Dilithium/ML-DSA, SPHINCS+/SLH-DSA,
    Falcon/FN-DSA, ChaCha20-Poly1305).

100% deterministic regex/keyword matching -- zero LLM/RAG involvement. Same
design principle as nessus_parser.py / trivy_parser.py for VAPT scanner
findings: identifying a known algorithm string is exact pattern matching, not
judgment, so there is nothing for an LLM to usefully add here.
"""
import json
import os
import re
from typing import List, Tuple, Any, Callable, Optional, Union

from .base_parser import BaseParser, is_image_file
from .finding_schema import Finding
from .control_mapper import map_pqc_findings_list

# ══════════════════════════════════════════════════════════════════════════════
# DETECTION GATE (can_parse)
# ══════════════════════════════════════════════════════════════════════════════

# Broad crypto/protocol/config vocabulary. PQC evidence isn't one fixed export
# format (unlike Nessus's native XML) -- it can be a TLS server config export, an
# sshd_config, an IPSec policy dump, a certificate listing, a DB encryption
# settings screen, etc. Any single one of these words alone is common in
# unrelated documents (an HR policy can say "encryption"), so -- mirroring
# nessus_parser.py's "weak_signal_count >= 2" pattern for exactly this kind of
# non-exclusive-signature situation -- at least 2 distinct hits are required.
_PQC_KEYWORDS = (
    "tls", "ssl", "cipher", "cipher suite", "ssh", "sshd", "ipsec", "vpn",
    "pki", "certificate", "x.509", "x509", "encryption", "encrypted",
    "key exchange", "key size", "keysize", "hsm", "keystore", "kms",
    "rsa", "ecc", "ecdsa", "ecdh", "aes", "sha", "algorithm", "handshake",
    "cryptograph", "signature algorithm", "diffie-hellman", "diffie hellman",
    "elliptic curve", "public key", "private key", "tde", "code signing",
    "code-signing", "firmware signing",
)

# Config-export filename extensions -- still content-gated (never filename-only,
# per every other parser's can_parse() convention), just given a lower keyword
# bar since the extension itself is already a meaningful signal.
_PQC_CONFIG_EXTENSIONS = (".conf", ".cnf", ".pem", ".crt", ".cer", ".key", ".p12", ".pfx", ".jks")


def _count_pqc_signals(sample_lower: str) -> int:
    return sum(1 for kw in _PQC_KEYWORDS if kw in sample_lower)


# ══════════════════════════════════════════════════════════════════════════════
# ALGORITHM LOOKUP TABLE
# ══════════════════════════════════════════════════════════════════════════════
# Each rule: (rule_id, regex, namer, quantum_status, crypto_category, severity)
#   rule_id         -- short stable key used to build a dedup-friendly plugin_id.
#   regex           -- compiled pattern matched against the raw evidence text.
#   namer           -- None (use the raw matched text as the display name),
#                       a fixed string, or a callable(match) -> str.
#   quantum_status  -- "VULNERABLE" | "WEAK" | "SAFE".
#   crypto_category -- human-readable category folded into title/description.
#   severity        -- fixed string, or callable(match) -> str for size/group-
#                       dependent rules (RSA key size, DH group number).

_SEV_INFO = "INFO"


def _rsa_sized_severity(m: "re.Match") -> str:
    size_m = re.search(r'(\d{3,5})', m.group(0))
    if size_m:
        try:
            return "CRITICAL" if int(size_m.group(1)) < 3072 else "HIGH"
        except ValueError:
            pass
    return "CRITICAL"


def _rsa_sized_namer(m: "re.Match") -> str:
    size_m = re.search(r'(\d{3,5})', m.group(0))
    return f"RSA{size_m.group(1)}" if size_m else m.group(0)


def _dh_group_severity(m: "re.Match") -> str:
    grp_m = re.search(r'(\d{1,2})', m.group(0))
    if grp_m:
        try:
            return "CRITICAL" if int(grp_m.group(1)) <= 14 else "HIGH"
        except ValueError:
            pass
    return "CRITICAL"


def _dh_group_namer(m: "re.Match") -> str:
    grp_m = re.search(r'(\d{1,2})', m.group(0))
    return f"Diffie-Hellman Group {grp_m.group(1)}" if grp_m else "Diffie-Hellman Group"


ALGORITHM_RULES: List[Tuple[str, "re.Pattern", Union[None, str, Callable], str, str, Union[str, Callable]]] = [
    # ── QUANTUM-VULNERABLE: asymmetric / key-exchange (broken by Shor's algorithm) ──
    ("rsa-sized", re.compile(r'\bRSA[\s\-_]?(?:512|1024|2048|3072|4096)\b', re.IGNORECASE),
     _rsa_sized_namer, "VULNERABLE", "Asymmetric Encryption (RSA)", _rsa_sized_severity),
    ("rsa-generic", re.compile(r'\bRSA\b(?!\s*[\d])', re.IGNORECASE),
     "RSA (unspecified key size)", "VULNERABLE", "Asymmetric Encryption (RSA)", "CRITICAL"),
    ("dsa", re.compile(r'\bDSA\b', re.IGNORECASE),
     "DSA", "VULNERABLE", "Asymmetric Digital Signature (DSA)", "CRITICAL"),
    ("dh-group", re.compile(r'\bDH\s*Group\s*(?:1[0-8]|[1-9])\b', re.IGNORECASE),
     _dh_group_namer, "VULNERABLE", "Key Exchange (Diffie-Hellman)", _dh_group_severity),
    ("dhe", re.compile(r'\bDHE\b', re.IGNORECASE),
     "DHE (Diffie-Hellman Ephemeral)", "VULNERABLE", "Key Exchange (Diffie-Hellman)", "HIGH"),
    ("dh-generic", re.compile(r'\bDiffie[\s\-]?Hellman\b', re.IGNORECASE),
     "Diffie-Hellman", "VULNERABLE", "Key Exchange (Diffie-Hellman)", "HIGH"),
    ("ecc-p256", re.compile(r'\b(?:P-256|secp256r1)\b', re.IGNORECASE),
     "ECC P-256 / secp256r1", "VULNERABLE", "Elliptic Curve Cryptography (ECC)", "HIGH"),
    ("ecc-p384", re.compile(r'\b(?:P-384|secp384r1)\b', re.IGNORECASE),
     "ECC P-384 / secp384r1", "VULNERABLE", "Elliptic Curve Cryptography (ECC)", "HIGH"),
    ("ecc-p521", re.compile(r'\b(?:P-521|secp521r1)\b', re.IGNORECASE),
     "ECC P-521 / secp521r1", "VULNERABLE", "Elliptic Curve Cryptography (ECC)", "HIGH"),
    ("ecc-secp256k1", re.compile(r'\bsecp256k1\b', re.IGNORECASE),
     "ECC secp256k1", "VULNERABLE", "Elliptic Curve Cryptography (ECC)", "HIGH"),
    ("ecc-x25519", re.compile(r'\b(?:Curve25519|X25519)\b', re.IGNORECASE),
     "Curve25519 / X25519", "VULNERABLE", "Elliptic Curve Cryptography (ECC)", "HIGH"),
    ("ecc-ed25519", re.compile(r'\bEd25519\b', re.IGNORECASE),
     "Ed25519", "VULNERABLE", "Elliptic Curve Cryptography (ECC)", "HIGH"),
    ("ecdsa", re.compile(r'\bECDSA\b', re.IGNORECASE),
     "ECDSA", "VULNERABLE", "Elliptic Curve Cryptography (ECC)", "HIGH"),
    ("ecdh", re.compile(r'\bECDH\b', re.IGNORECASE),
     "ECDH", "VULNERABLE", "Elliptic Curve Cryptography (ECC)", "HIGH"),
    ("ecc-generic", re.compile(r'\bECC\b', re.IGNORECASE),
     "ECC (generic elliptic-curve reference)", "VULNERABLE", "Elliptic Curve Cryptography (ECC)", "HIGH"),

    # ── CLASSICALLY WEAK / DEPRECATED (not PQC-specific, still flagged) ──
    ("md5", re.compile(r'\bMD5\b', re.IGNORECASE),
     "MD5", "WEAK", "Hash Function", "HIGH"),
    ("sha1", re.compile(r'\bSHA[\s\-_]?1\b', re.IGNORECASE),
     "SHA-1", "WEAK", "Hash Function", "HIGH"),
    ("3des", re.compile(r'\b(?:3DES|Triple[\s\-]?DES|TripleDES)\b', re.IGNORECASE),
     "3DES / Triple DES", "WEAK", "Symmetric Cipher", "CRITICAL"),
    ("des", re.compile(r'\bDES\b', re.IGNORECASE),
     "DES", "WEAK", "Symmetric Cipher", "CRITICAL"),
    ("rc4", re.compile(r'\bRC4\b', re.IGNORECASE),
     "RC4", "WEAK", "Symmetric Cipher", "CRITICAL"),
    ("sslv2", re.compile(r'\bSSL\s?v?2\b', re.IGNORECASE),
     "SSLv2", "WEAK", "Protocol Version", "CRITICAL"),
    ("sslv3", re.compile(r'\bSSL\s?v?3\b', re.IGNORECASE),
     "SSLv3", "WEAK", "Protocol Version", "CRITICAL"),
    ("tls10", re.compile(r'\bTLS\s?v?1\.0\b', re.IGNORECASE),
     "TLS 1.0", "WEAK", "Protocol Version", "CRITICAL"),
    ("tls11", re.compile(r'\bTLS\s?v?1\.1\b', re.IGNORECASE),
     "TLS 1.1", "WEAK", "Protocol Version", "CRITICAL"),
    ("cbc-mode", re.compile(r'\bCBC\b', re.IGNORECASE),
     "CBC-mode cipher (non-AEAD)", "WEAK", "Cipher Mode", "MEDIUM"),

    # ── QUANTUM-SAFE / NIST PQC-SELECTED ──
    ("aes256-gcm", re.compile(r'\bAES[\s\-_]?256[\s\-_]?GCM\b', re.IGNORECASE),
     "AES-256-GCM", "SAFE", "Symmetric Cipher (AEAD)", _SEV_INFO),
    ("aes256", re.compile(r'\bAES[\s\-_]?256\b', re.IGNORECASE),
     "AES-256", "SAFE", "Symmetric Cipher", _SEV_INFO),
    ("aes128", re.compile(r'\bAES[\s\-_]?128\b', re.IGNORECASE),
     "AES-128 (quantum-safe but AES-256 preferred)", "SAFE", "Symmetric Cipher", _SEV_INFO),
    ("sha384", re.compile(r'\bSHA[\s\-_]?384\b', re.IGNORECASE),
     "SHA-384", "SAFE", "Hash Function", _SEV_INFO),
    ("sha512", re.compile(r'\bSHA[\s\-_]?512\b', re.IGNORECASE),
     "SHA-512", "SAFE", "Hash Function", _SEV_INFO),
    ("sha256", re.compile(r'\bSHA[\s\-_]?256\b', re.IGNORECASE),
     "SHA-256 (acceptable minimum)", "SAFE", "Hash Function", _SEV_INFO),
    ("sha3", re.compile(r'\bSHA[\s\-_]?3\b', re.IGNORECASE),
     "SHA-3", "SAFE", "Hash Function", _SEV_INFO),
    ("kyber", re.compile(r'\b(?:CRYSTALS[\s\-]?Kyber|ML[\s\-]?KEM)\b', re.IGNORECASE),
     "CRYSTALS-Kyber / ML-KEM", "SAFE", "PQC Key Encapsulation (NIST-selected)", _SEV_INFO),
    ("dilithium", re.compile(r'\b(?:CRYSTALS[\s\-]?Dilithium|ML[\s\-]?DSA)\b', re.IGNORECASE),
     "CRYSTALS-Dilithium / ML-DSA", "SAFE", "PQC Digital Signature (NIST-selected)", _SEV_INFO),
    ("sphincs", re.compile(r'\b(?:SPHINCS\+|SLH[\s\-]?DSA)\b', re.IGNORECASE),
     "SPHINCS+ / SLH-DSA", "SAFE", "PQC Digital Signature (NIST-selected)", _SEV_INFO),
    ("falcon", re.compile(r'\b(?:Falcon|FN[\s\-]?DSA)\b', re.IGNORECASE),
     "Falcon / FN-DSA", "SAFE", "PQC Digital Signature (NIST-selected)", _SEV_INFO),
    ("chacha20", re.compile(r'\bChaCha20[\s\-]?Poly1305\b', re.IGNORECASE),
     "ChaCha20-Poly1305", "SAFE", "Symmetric Cipher (AEAD)", _SEV_INFO),
]

# Per-algorithm precise remediation (overrides generic _REMEDIATION_VULNERABLE where matched).
# Key = lowercase substring of algo_name or crypto_category combined string.
# CRITICAL: order matters -- more specific keys MUST come before generic catch-alls.
# All ECC-family findings share crypto_category "Elliptic Curve Cryptography (ECC)",
# so curve25519 / x25519 / secp / ecdsa / ecdh must appear BEFORE "elliptic curve".
_REMEDIATION_BY_ALGO = [
    # ── Curve25519 / X25519 (most specific -- check before generic ECC) ───────
    ("curve25519",
        "Curve25519 / X25519 is quantum-vulnerable to Shor's algorithm.\n"
        "IMMEDIATE ACTIONS:\n"
        "  1. Upgrade to hybrid PQC mode: X25519MLKEM768 (X25519 + ML-KEM-768, FIPS 203).\n"
        "     NGINX: ssl_ecdh_curve X25519MLKEM768:X25519;\n"
        "     (Provides both classical and post-quantum protection in one handshake -- "
        "'Harvest Now, Decrypt Later' safe.)\n"
        "  2. For SSH key exchange: add sntrup761x25519-sha512@openssh.com to "
        "sshd_config KexAlgorithms (OpenSSH 9.0+).\n"
        "  3. Long-term: migrate to ML-KEM-768 standalone (FIPS 203) once all clients support it.\n"
        "  NIST Reference: FIPS 203 (ML-KEM-768 = security level 3, equivalent to AES-192)."
    ),
    # ── X25519 (catches 'X25519' in algo_name without Curve25519 prefix) ─────
    ("x25519",
        "X25519 (Curve25519) is quantum-vulnerable to Shor's algorithm.\n"
        "IMMEDIATE ACTIONS:\n"
        "  1. Upgrade to hybrid PQC: X25519MLKEM768 in NGINX ssl_ecdh_curve.\n"
        "     ssl_ecdh_curve X25519MLKEM768:X25519;\n"
        "  2. For SSH: use sntrup761x25519-sha512@openssh.com (OpenSSH 9.0+ hybrid KEX).\n"
        "  3. Long-term: ML-KEM-768 (FIPS 203) for full post-quantum key encapsulation.\n"
        "  NIST Reference: FIPS 203."
    ),
    # ── Named secp curves (secp256r1 / secp384r1 / secp521r1) ─────────────────
    ("secp",
        "Named elliptic curves (secp256r1 / secp384r1 / secp521r1) are quantum-vulnerable.\n"
        "IMMEDIATE ACTIONS:\n"
        "  1. For TLS key agreement: replace with X25519MLKEM768 hybrid as first preference.\n"
        "     NGINX: ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\n"
        "  2. For TLS certificates using secp384r1: reissue with ML-DSA-65 (FIPS 204) "
        "once your CA supports post-quantum hybrid certs.\n"
        "  3. Track IETF TLS 1.3 hybrid key exchange drafts (draft-ietf-tls-hybrid-design) "
        "for NGINX/OpenSSL 3.x adoption timelines.\n"
        "  NIST Reference: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), NIST SP 800-186."
    ),
    # ── ECDSA (signature scheme, separate from ECDH key exchange) ─────────────
    ("ecdsa",
        "ECDSA signatures are broken by Shor's algorithm -- the discrete logarithm "
        "over elliptic curves is efficiently solvable on a quantum computer.\n"
        "IMMEDIATE ACTIONS:\n"
        "  1. Replace ECDSA TLS/SSH certificates with ML-DSA (FIPS 204) once your CA supports it.\n"
        "  2. Interim: ECDSA P-256/P-384 is still safe classically -- prioritise migration "
        "of long-lived certificates and code-signing keys first.\n"
        "  3. For NGINX cipher suites with ECDSA: ensure ssl_ecdh_curve includes "
        "X25519MLKEM768 to protect the key exchange layer even before cert migration.\n"
        "  4. For JWT / API tokens / code signing: migrate to ML-DSA-44 or ML-DSA-65.\n"
        "  5. For SSH host keys: switch to Ed25519 (interim) or ML-DSA-65 (long-term).\n"
        "  NIST Reference: FIPS 204 (ML-DSA replaces ECDSA), NIST IR 8413 (Falcon/FN-DSA)."
    ),
    # ── ECDH (key encapsulation / key agreement) ──────────────────────────────
    ("ecdh",
        "ECDH key agreement is broken by Shor's algorithm.\n"
        "IMMEDIATE ACTIONS:\n"
        "  1. Replace ECDH with ML-KEM-768 (FIPS 203 / CRYSTALS-Kyber-768) for "
        "post-quantum key encapsulation.\n"
        "  2. Interim hybrid mode: X25519MLKEM768 in NGINX provides both classical "
        "and PQC protection simultaneously.\n"
        "     NGINX: ssl_ecdh_curve X25519MLKEM768:X25519;\n"
        "  3. For IPSec/IKEv2: add ML-KEM KEM groups in IKE SA proposals per RFC 9370.\n"
        "  4. For TLS 1.3 clients not yet supporting X25519MLKEM768: "
        "keep X25519 as fallback in ssl_ecdh_curve list.\n"
        "  NIST Reference: FIPS 203 (ML-KEM), NIST SP 800-56C Rev 2."
    ),
    # ── Generic ECC catch-all (any other ECC not matched above) ───────────────
    ("elliptic curve",
        "Elliptic Curve Cryptography (ECC) is broken by Shor's algorithm. "
        "Both ECDH (key agreement) and ECDSA (signatures) must be migrated.\n"
        "IMMEDIATE ACTIONS:\n"
        "  1. Key exchange: replace ECDH with ML-KEM-768 (FIPS 203). "
        "Hybrid interim: X25519MLKEM768.\n"
        "  2. Signatures: replace ECDSA with ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).\n"
        "  3. NGINX: ssl_ecdh_curve X25519MLKEM768:X25519; (hybrid PQC key exchange).\n"
        "  4. Reissue all ECC certificates when your CA supports post-quantum or hybrid certs.\n"
        "  NIST Reference: FIPS 203, FIPS 204, FIPS 205."
    ),
    # ── RSA ───────────────────────────────────────────────────────────────────
    ("rsa",
        "RSA is broken by Shor's algorithm on a sufficiently large quantum computer.\n"
        "IMMEDIATE ACTIONS:\n"
        "  1. Inventory all RSA key usages: TLS certificates, SSH host keys, "
        "code-signing, JWT tokens, S/MIME.\n"
        "  2. For TLS key exchange: disable static-RSA cipher suites (non-ECDHE). "
        "ECDHE-RSA-* (PFS) is lower risk but still needs migration.\n"
        "     NGINX interim: ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384;\n"
        "  3. For TLS certificates: reissue as ECDSA P-256 (interim) then "
        "ML-DSA-65 (FIPS 204) when CA chains support it.\n"
        "  4. For SSH host/user keys: switch to Ed25519 (interim) or ML-DSA-65.\n"
        "  5. For code/firmware signing: move to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).\n"
        "  6. Prioritise RSA-2048 and below for immediate migration; "
        "RSA-4096 has more runway but still requires planning.\n"
        "  NIST Reference: FIPS 204 (ML-DSA), FIPS 203 (ML-KEM), NIST SP 800-131A Rev 2."
    ),
    # ── DH Group (specific, before generic Diffie-Hellman) ───────────────────
    ("dh group",
        "DH group-based key exchange is quantum-vulnerable to Shor's algorithm.\n"
        "IMMEDIATE ACTIONS:\n"
        "  1. Replace DHE groups with ML-KEM-768 (FIPS 203) for PQC key encapsulation.\n"
        "  2. For IKEv2/IPSec: add ML-KEM IKE groups (RFC 9370) to the SA proposal list.\n"
        "  3. Interim minimum: DH group 14 (2048-bit); prefer group 16 (4096-bit) or "
        "group 19 (ECDHE P-256) while migrating.\n"
        "  4. Disable DH groups 1, 2, 5, 22, 23, 24 (below 2048-bit) immediately -- "
        "these are classically weak too.\n"
        "  NIST Reference: FIPS 203, NIST SP 800-77 Rev 1."
    ),
    # ── Diffie-Hellman generic ────────────────────────────────────────────────
    ("diffie-hellman",
        "Diffie-Hellman key exchange is broken by Shor's algorithm.\n"
        "IMMEDIATE ACTIONS:\n"
        "  1. Replace static DH cipher suites with ECDHE (interim) or ML-KEM-768 (long-term).\n"
        "  2. Disable DHE cipher suites below group 14 (2048-bit) immediately.\n"
        "  3. For IKEv2/IPSec: configure post-quantum KEM groups per RFC 9370.\n"
        "  4. Migrate to ML-KEM-768 (FIPS 203) for all new key exchange implementations.\n"
        "  NIST Reference: FIPS 203, NIST SP 800-56A Rev 3."
    ),
]


def _get_remediation_vulnerable(algo_name: str, crypto_category: str) -> str:
    """Return the most specific available remediation for a VULNERABLE algorithm.
    Uses an ordered list (not dict) so that more-specific entries are always checked first.
    Falls back to the generic _REMEDIATION_VULNERABLE if no specific entry matches.

    Matching: checks if the key string is a substring of the combined
    'algo_name + crypto_category' (lower-cased). All ECC findings share
    crypto_category 'Elliptic Curve Cryptography (ECC)', so algorithm-specific
    keys (curve25519, x25519, secp, ecdsa, ecdh) must appear before 'elliptic curve'
    in the list -- which they do."""
    combined = f"{algo_name} {crypto_category}".lower()
    for key, text in _REMEDIATION_BY_ALGO:
        if key in combined:
            return text
    return _REMEDIATION_VULNERABLE


_REMEDIATION_WEAK = (
    "Disable this deprecated/weak cryptographic algorithm or protocol version immediately and "
    "replace it with a modern, non-deprecated alternative (AES-256-GCM, SHA-384+, TLS 1.2+ with "
    "strong cipher suites). This is independent of quantum readiness -- it is already breakable "
    "with classical computing -- but should be tracked alongside the broader PQC migration plan."
)
_REMEDIATION_SAFE = (
    "No quantum-readiness action required for this algorithm today. Continue monitoring NIST PQC "
    "guidance and prefer AES-256/SHA-384+ over smaller-margin variants (e.g. AES-128, SHA-256) "
    "where practical, since Grover's algorithm only gives a quadratic quantum speed-up against them."
)


def _resolve(value, m):
    if value is None:
        return m.group(0)
    if callable(value):
        return value(m)
    return value


# ══════════════════════════════════════════════════════════════════════════════
# TARGET / ASSET CONTEXT EXTRACTION (best-effort)
# ══════════════════════════════════════════════════════════════════════════════

_ASSET_HEADING_RE = re.compile(
    r'(?im)^\s*(?:host|target|system|asset|server|hostname|device|node|ip\s*address)\s*[:=]\s*(.+)$'
)


def _find_asset_context(content: str, match_start: int, filename: str) -> str:
    """Best-effort surrounding asset/heading context for a match -- looks
    backward up to ~800 chars for the nearest 'Host:'/'Target:'/'System:'-style
    line. Falls back to the filename when no such heading is found."""
    window_start = max(0, match_start - 800)
    window = content[window_start:match_start]
    hits = list(_ASSET_HEADING_RE.finditer(window))
    if hits:
        return hits[-1].group(0).strip()
    return filename


def _line_containing(content: str, start: int, end: int) -> str:
    """Returns the full line(s) containing [start:end), guaranteed to be a real
    substring of `content` (grounding requirement) -- never paraphrased."""
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", end)
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end].strip() or content[start:end]


# ══════════════════════════════════════════════════════════════════════════════
# CA / KEY / PROTOCOL LAYER CLASSIFICATION (best-effort, Enhancement 1)
# ══════════════════════════════════════════════════════════════════════════════

_CA_LABELS = ("certificate", "ca ", "ca:", "signature algorithm", "issued by", "x.509", "x509")
_KEY_LABELS = ("key exchange", "key size", "key algorithm", "kex", "public key", "private key", "key:")
_PROTOCOL_LABELS = (
    "protocol", "tls version", "ssl version", "ike version", "ipsec phase",
    "ssh version", "phase 1", "phase 2",
)


def _classify_crypto_layer(content: str, match_start: int, match_end: int) -> str:
    """Best-effort classification of which crypto-config "layer" (CA/KEY/
    PROTOCOL) a match belongs to, based on the nearest preceding field label on
    the same line or within ~120 chars before the match. Returns "" if no
    recognizable label is found nearby -- never guessed."""
    window_start = max(0, match_start - 120)
    window = content[window_start:match_start].lower()

    def _last_label_index(labels):
        best = -1
        for label in labels:
            idx = window.rfind(label)
            if idx > best:
                best = idx
        return best

    ca_idx = _last_label_index(_CA_LABELS)
    key_idx = _last_label_index(_KEY_LABELS)
    proto_idx = _last_label_index(_PROTOCOL_LABELS)

    best_layer = ""
    best_idx = -1
    for layer, idx in (("CA", ca_idx), ("KEY", key_idx), ("PROTOCOL", proto_idx)):
        if idx > best_idx:
            best_idx = idx
            best_layer = layer

    if best_idx == -1:
        return ""
    return best_layer


# ══════════════════════════════════════════════════════════════════════════════
# EXPOSURE CONTEXT CLASSIFICATION (best-effort, Enhancement 2)
# ══════════════════════════════════════════════════════════════════════════════

_EXTERNAL_SIGNALS = (
    "external", "internet-facing", "internet facing", "public", "dmz",
    "wan-facing", "external-facing", "perimeter",
)
_INTERNAL_SIGNALS = (
    "internal", "internal-only", "lan", "intranet", "private network", "on-prem",
)
# Word-boundary compiled versions of the above -- bare `sig in search_text`
# containment let short signals like "lan" false-match inside unrelated words
# (e.g. "Load Balancer" contains "lan" inside "baLANcer"), wrongly flipping a
# genuinely EXTERNAL-exposed asset to unclassified/INTERNAL and silently
# depressing its HNDL risk factor. Same class of bug already guarded against
# elsewhere in this codebase (see get_actionable_remediation()'s word-boundary
# note in this file). Phrases with spaces (e.g. "internet facing") still match
# correctly since \b anchors on the whole phrase's start/end.
_EXTERNAL_SIGNAL_RE = re.compile(
    r'\b(?:' + '|'.join(re.escape(s) for s in _EXTERNAL_SIGNALS) + r')\b', re.IGNORECASE
)
_INTERNAL_SIGNAL_RE = re.compile(
    r'\b(?:' + '|'.join(re.escape(s) for s in _INTERNAL_SIGNALS) + r')\b', re.IGNORECASE
)


def _classify_exposure(content: str, match_start: int, asset_ctx: str, filename: str) -> str:
    """Best-effort EXTERNAL/INTERNAL exposure classification for a match, based
    on nearby context (asset context line + a ~300-char window around the
    match + filename). Returns "" if both/neither found."""
    window_start = max(0, match_start - 300)
    window_end = min(len(content), match_start + 300)
    search_text = (
        (asset_ctx or "") + " " + content[window_start:window_end] + " " + (filename or "")
    ).lower()

    has_external = bool(_EXTERNAL_SIGNAL_RE.search(search_text))
    has_internal = bool(_INTERNAL_SIGNAL_RE.search(search_text))

    if has_external and not has_internal:
        return "EXTERNAL"
    if has_internal and not has_external:
        return "INTERNAL"
    return ""


# ══════════════════════════════════════════════════════════════════════════════
# PORT EXTRACTION (best-effort, Enhancement 3)
# ══════════════════════════════════════════════════════════════════════════════

_PORT_LABEL_RE = re.compile(r'\bport\s*[:=]?\s*(\d{1,5})\b', re.IGNORECASE)
_PORT_SUFFIX_RE = re.compile(r':(\d{1,5})\b')


def _find_port(content: str, match_start: int, match_end: int) -> str:
    """Best-effort nearby port number for a match -- searches the containing
    line plus a ~200-char window before/after for a 'Port: NNN' style label or
    a ':NNN' suffix immediately following a hostname/IP-looking token. Returns
    "" if no such reference is nearby -- never a fabricated/default port."""
    window_start = max(0, match_start - 200)
    window_end = min(len(content), match_end + 200)
    line = _line_containing(content, match_start, match_end)
    window = content[window_start:window_end]

    for text in (line, window):
        m = _PORT_LABEL_RE.search(text)
        if m:
            return m.group(1)

    for text in (line, window):
        m = _PORT_SUFFIX_RE.search(text)
        if m:
            return m.group(1)

    return ""


# ══════════════════════════════════════════════════════════════════════════════
# ENVIRONMENT CLASSIFICATION (best-effort, Enhancement 4)
# ══════════════════════════════════════════════════════════════════════════════

_PROD_RE = re.compile(r'\b(?:prod|production)\b', re.IGNORECASE)
_NON_PROD_RE = re.compile(
    r'\b(?:dev|development|test|testing|staging|uat|qa|sandbox)\b', re.IGNORECASE
)


def _classify_environment(content: str, match_start: int, asset_ctx: str, filename: str) -> str:
    """Best-effort PROD/NON_PROD environment classification for a match, based
    on asset context + filename + a nearby content window. Word-boundary
    matched to avoid false positives (e.g. "product" must not match "prod").
    Returns "" if both/neither found."""
    window_start = max(0, match_start - 300)
    window_end = min(len(content), match_start + 300)
    search_text = (
        (asset_ctx or "") + " " + content[window_start:window_end] + " " + (filename or "")
    )

    has_prod = bool(_PROD_RE.search(search_text))
    has_non_prod = bool(_NON_PROD_RE.search(search_text))

    if has_prod and not has_non_prod:
        return "PROD"
    if has_non_prod and not has_prod:
        return "NON_PROD"
    return ""


# ── Asset Category keyword maps (Whiteboard / RFP schema) ────────────────────
# Order matters: more specific categories are checked first so that e.g.
# "palo alto firewall" matches "Firewall" before the generic "Server" catch.
_ASSET_CATEGORY_RULES = [
    # Category label        Keyword signals (any match -> this category)
    # ORDER MATTERS: more specific/less ambiguous categories first.
    ("Firewall",            ("firewall", "palo alto", "pan-os", "fortigate", "fortinet",
                             "checkpoint", "check point", "cisco asa", "cisco firepower",
                             "firepower", "sophos", "pfsense", "iptables")),
    ("VPN",                 ("vpn", "ipsec", "globalprotect", "anyconnect", "pulse secure",
                             "fortivpn", "ssl vpn", "ikev2", "ikev1", "ike ", "strongswan",
                             "openvpn", "wireguard", "l2tp", "pptp", "isakmp")),
    # Cloud BEFORE PKI/HSM: AWS/Azure/GCP configs contain x.509/certificate
    # so PKI/HSM would fire wrongly if checked before Cloud.
    ("Cloud",               ("aws", "amazon", "aws kms", "aws iam",
                             "azure", "azure key vault", "azure blob", "azure ad",
                             "gcp", "google cloud", "gcp kms", "cloud hsm",
                             "cloudfront", "s3 bucket", "ec2", "eks", "aks", "gke",
                             "lambda", "key management service")),
    ("PKI / HSM",           ("pki", "certificate authority", "ca certificate", "root ca",
                             "intermediate ca", "hsm", "safenet", "thales", "luna",
                             "venafi", "entrust", "digicert", "microsoft ca", "adcs",
                             "x.509", "x509", "crl", "ocsp", "est protocol")),
    ("Database",            ("oracle", "oracle db", "mysql", "postgresql", "postgres",
                             "ms sql", "mssql", "sql server", "mongodb", "tde",
                             "transparent data encryption", "database encryption",
                             "sqlnet", "wallet_root", "tde_configuration",
                             "db2", "mariadb", "sybase")),
    ("Load Balancer",       ("nginx", "f5", "big-ip", "citrix adc", "netscaler",
                             "haproxy", "load balancer", "load-balancer", "reverse proxy",
                             "api gateway")),
    ("Web / App",           ("web application", "web app", "webapp", "apache", "tomcat",
                             "iis", "jetty", "django", "flask", "spring",
                             "rest api", "graphql", "oauth", "jwt",
                             "ssl_ciphers", "sslengine")),
    ("SSH / Remote Access", ("sshd", "ssh", "openssh", "putty", "rdp", "remote desktop",
                             "telnet", "jump server", "bastion")),
    # 'host'/'vm'/'server' removed: match inside server_name/ssh_host_rsa_key/vmware_tools
    ("Server",              ("linux", "ubuntu", "centos", "rhel", "debian",
                             "windows server", "linux server",
                             "virtual machine", "esxi", "vmware",
                             "hypervisor", "bare metal")),
]


def _classify_asset_category(asset_ctx: str, filename: str, content_window: str) -> str:
    """
    Deterministic asset category classifier.
    Maps the finding's asset_name, filename and a nearby content window
    to one of the Whiteboard/RFP-defined asset categories.
    100% offline keyword matching — never infers or guesses.
    Returns "Unknown" when no category signal is found.
    """
    combined = f"{asset_ctx or ''} {filename or ''} {content_window or ''}".lower()
    for category, keywords in _ASSET_CATEGORY_RULES:
        if any(kw in combined for kw in keywords):
            return category
    return "Unknown"


# ══════════════════════════════════════════════════════════════════════════════
# OEM / VENDOR PQC READINESS MATRIX  (best-effort, Enhancement C)
# ══════════════════════════════════════════════════════════════════════════════
# Static, manually-curated reference table (src/core/knowledge/pqc_oem_readiness.json)
# mapping vendor/product names to their known PQC readiness status. Loaded once
# at module level -- same path-resolution convention as
# controls_data.py::_merge_knowledge_base() (os.path.join(dirname, "knowledge",
# filename)), just one directory up since this module lives in
# src/core/parsers/ rather than src/core/. Missing/invalid file is non-fatal:
# OEM matching just yields no results, same "fail open, never crash" contract
# as _merge_knowledge_base().

_OEM_READINESS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "knowledge", "pqc_oem_readiness.json"
)


def _load_oem_readiness_table() -> dict:
    try:
        with open(_OEM_READINESS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


_OEM_READINESS_TABLE = _load_oem_readiness_table()


def _build_oem_matchers() -> List[Tuple["re.Pattern", str, str, str]]:
    """Builds (compiled_regex, product_name, vendor, status) tuples for every
    product-name key and vendor name in the readiness table. Each pattern
    matches its literal name on real word boundaries (custom lookaround, not
    bare substring containment) -- e.g. "F5" must not match inside "UTF5".
    Sorted longest-name-first so a more specific name (e.g. "Palo Alto
    PAN-OS") is tried before a shorter, less specific one (e.g. a bare vendor
    name like "Oracle") that might also appear in the same text."""
    matchers = []
    for product_name, info in _OEM_READINESS_TABLE.items():
        if not isinstance(info, dict):
            continue
        vendor = info.get("vendor", "")
        status = info.get("status", "")
        names = {product_name}
        if vendor:
            names.add(vendor)
        for name in names:
            if not name:
                continue
            pattern = re.compile(
                r'(?<![A-Za-z0-9])' + re.escape(name) + r'(?![A-Za-z0-9])', re.IGNORECASE
            )
            # Sort key is the literal matched name's own length (not the
            # product_name key's length) -- a short vendor name like "Oracle"
            # must not be tried before a longer, more specific product name
            # just because it happens to belong to a long product_name key.
            matchers.append((len(name), pattern, product_name, vendor, status))
    matchers.sort(key=lambda t: -t[0])
    return [(pattern, product_name, vendor, status) for _len, pattern, product_name, vendor, status in matchers]


_OEM_MATCHERS = _build_oem_matchers()


def _match_oem_readiness(content: str, filename: str) -> Tuple[str, str, str]:
    """Best-effort OEM/vendor PQC-readiness lookup against the static
    pqc_oem_readiness.json reference table. Checks both evidence content and
    filename. Returns (product_name, vendor, status), or ("", "", "") if
    nothing matched -- never fabricated."""
    if not _OEM_MATCHERS:
        return "", "", ""
    haystack = f"{content or ''} {filename or ''}"
    for pattern, product_name, vendor, status in _OEM_MATCHERS:
        if pattern.search(haystack):
            return product_name, vendor, status
    return "", "", ""


# ══════════════════════════════════════════════════════════════════════════════
# BLOCK-HEADING CONTEXT  (best-effort, supports Enhancements B & D)
# ══════════════════════════════════════════════════════════════════════════════

_DASH_LINE_RE = re.compile(r'^[-_=]{3,}$')


def _find_block_heading_context(content: str, match_start: int) -> str:
    """Best-effort broader context for a match, used ONLY to enrich
    finding.asset_name as a fallback when the stricter Phase-1
    _find_asset_context() found no 'Host:'/'Target:'-style heading (i.e. fell
    back to the bare filename) -- never overwrites a real Phase-1 match, and
    never touches _find_asset_context() itself.

    Narrative evidence (an architecture diagram's extracted text, a free-form
    device write-up) often labels a block with plain heading lines instead of
    'Label: value' pairs, e.g.:
        Internet Banking App - External Production System
        Palo Alto PAN-OS Firewall Configuration
        IPSec VPN Profile
        -----------------------------
        Certificate : RSA2048
    This walks back from the match to the start of the current blank-line
    delimited paragraph and collects the heading lines at its top -- stopping
    at the first dashed separator or 'label: value' line. Returns "" if
    nothing usable is found.
    """
    para_start = content.rfind("\n\n", 0, match_start)
    para_start = 0 if para_start == -1 else para_start + 2
    para_text = content[para_start:match_start]

    heading_lines = []
    for line in para_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if _DASH_LINE_RE.match(stripped):
            break
        if ":" in stripped or "=" in stripped:
            break
        heading_lines.append(stripped)
    return " ".join(heading_lines)


# ══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY CHAIN PARSING  (evidence-stated only, Enhancement D)
# ══════════════════════════════════════════════════════════════════════════════

_CHAIN_LINE_RE = re.compile(r'^.+(?:->|→|\|).+$')
_CHAIN_SPLIT_RE = re.compile(r'->|→|\|')
_VERTICAL_CONNECTOR_TOKENS = ("|", "│", "▼")


def _parse_dependency_chains(content: str) -> List[List[str]]:
    """Best-effort extraction of EXPLICITLY-stated dependency/architecture
    chains from evidence text. Only surfaces a chain when the evidence text
    itself states one -- never infers/guesses topology from nothing.

    Supports two formats:
      1. Single-line arrow/pipe chain: 'A -> B -> C', 'A | B | C', 'A -> B -> C'
         (arrow variants), comma-free simple separator-delimited chains.
      2. A simple vertical chain mirroring an architecture diagram's own
         layout -- one node name per line, delimited by connector-only lines
         ('|', a vertical bar glyph, or a downward-triangle glyph). Requires
         at least one such connector line to be present, so ordinary
         multi-line paragraph text is never mistaken for a chain.

    Returns [] if nothing matches.
    """
    chains: List[List[str]] = []
    lines = content.splitlines()

    # ── Format 1: single-line arrow/pipe chains ──
    for line in lines:
        stripped = line.strip()
        if not stripped or not _CHAIN_LINE_RE.match(stripped):
            continue
        segments = [seg.strip() for seg in _CHAIN_SPLIT_RE.split(stripped)]
        segments = [seg for seg in segments if seg]
        if len(segments) >= 2:
            chains.append(segments)

    # ── Format 2: simple vertical chain (node / connector / node / ...) ──
    current: List[str] = []
    saw_connector = False
    for line in lines + [""]:  # sentinel blank line flushes the last run
        stripped = line.strip()
        if not stripped:
            if saw_connector and len(current) >= 2:
                chains.append(current)
            current, saw_connector = [], False
            continue
        if stripped in _VERTICAL_CONNECTOR_TOKENS:
            saw_connector = True
            continue
        if _CHAIN_LINE_RE.match(stripped):
            # A single-line arrow chain, not a bare vertical node name --
            # already captured by Format 1 above.
            if saw_connector and len(current) >= 2:
                chains.append(current)
            current, saw_connector = [], False
            continue
        current.append(stripped)

    return chains


# ══════════════════════════════════════════════════════════════════════════════
# PARSER
# ══════════════════════════════════════════════════════════════════════════════

class PQCParser(BaseParser):
    """Deterministic Post-Quantum Cryptography readiness scanner. Parses plain
    text / HTML / XML / PDF-extracted evidence (TLS, SSH, IPSec, PKI, DB
    encryption, HSM/KMS, code-signing config exports) and flags cryptographic
    algorithms as Quantum-Vulnerable, Classically-Weak, or Quantum-Safe.
    """

    def can_parse(self, filename: str, content: str) -> bool:
        if not content:
            return False
        # Guard: reject image files regardless of their filename.
        if is_image_file(filename):
            return False

        sample = content.lower()
        weak_signal_count = _count_pqc_signals(sample)
        if weak_signal_count >= 2:
            return True

        # Recognizable config-export extension -- still content-gated (a lower
        # bar of 1 keyword hit, not filename-only), since the extension alone
        # is already meaningful signal for this file type.
        if filename.lower().endswith(_PQC_CONFIG_EXTENSIONS) and weak_signal_count >= 1:
            return True

        return False

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], List[Finding]]:
        if not content:
            return [], []

        actionable_findings: List[Finding] = []
        info_findings: List[Finding] = []
        accepted_spans: List[Tuple[int, int]] = []

        def _overlaps(start: int, end: int) -> bool:
            for s, e in accepted_spans:
                if start < e and end > s:
                    return True
            return False

        for rule_id, pattern, namer, quantum_status, crypto_category, severity_rule in ALGORITHM_RULES:
            for m in pattern.finditer(content):
                start, end = m.start(), m.end()
                if _overlaps(start, end):
                    continue
                accepted_spans.append((start, end))

                algo_name = _resolve(namer, m)
                severity = _resolve(severity_rule, m)
                evidence_line = _line_containing(content, start, end)
                asset_ctx = _find_asset_context(content, start, filename)

                # Enhancement 2: exposure-based severity escalation (EXTERNAL only).
                exposure_context = _classify_exposure(content, start, asset_ctx, filename)

                # Second-pass inference: if keyword detection couldn't determine exposure
                # (the config file doesn't literally say "external" / "internal"), infer
                # it from structural signals — same approach as Nessus/Qualys which assign
                # AV:N (Network/External) based on service type, not document vocabulary.
                if not exposure_context:
                    _cat = getattr(finding, "asset_category", "") if False else ""
                    # Use the already-set category if available, else classify now.
                    _cat_window_exp = content[max(0, start - 400): min(len(content), end + 400)]
                    _inferred_cat = _classify_asset_category(asset_ctx, filename, _cat_window_exp)

                    # Definitionally external-facing asset categories:
                    _EXTERNAL_CATEGORIES = {"Load Balancer", "Firewall", "VPN", "Web / App"}
                    # Definitionally internal/server-side categories:
                    _INTERNAL_CATEGORIES = {"Database", "Server", "SSH / Remote Access"}

                    # Structural TLS signals — a config that terminates TLS on 443 is
                    # internet-facing by function even if it never says "external".
                    _content_lower = content.lower()
                    _tls_external_signals = (
                        "listen 443" in _content_lower or
                        "ssl_certificate" in _content_lower or
                        "server_name" in _content_lower or
                        "ssl on" in _content_lower
                    )

                    # Definitionally external-facing categories:
                    # Cloud KMS/HSM = public cloud APIs (HNDL threat applies)
                    # PKI/HSM = public CA endpoints (OCSP/CRL are internet-facing)
                    _EXTERNAL_CATEGORIES = {
                        "Load Balancer", "Firewall", "VPN", "Web / App",
                        "Cloud", "PKI / HSM"
                    }
                    # Definitionally internal/server-side categories:
                    _INTERNAL_CATEGORIES = {"Database", "Server", "SSH / Remote Access"}

                    if _inferred_cat in _EXTERNAL_CATEGORIES or _tls_external_signals:
                        exposure_context = "EXTERNAL"
                    elif _inferred_cat in _INTERNAL_CATEGORIES:
                        exposure_context = "INTERNAL"

                if exposure_context == "EXTERNAL":
                    if severity == "MEDIUM":
                        severity = "HIGH"
                    elif severity == "HIGH":
                        severity = "CRITICAL"

                if quantum_status == "VULNERABLE":
                    title = f"Quantum-Vulnerable Algorithm Detected: {algo_name}"
                    description = (
                        f"Evidence in '{filename}' shows use of {algo_name} ({crypto_category}). "
                        f"This algorithm is quantum-vulnerable: a sufficiently large quantum computer "
                        f"running Shor's algorithm can efficiently break it, undermining the "
                        f"confidentiality/integrity of anything protected by it once such hardware "
                        f"exists (including data captured today and decrypted later -- "
                        f"'harvest now, decrypt later')."
                    )
                    remediation = _get_remediation_vulnerable(algo_name, crypto_category)
                elif quantum_status == "WEAK":
                    title = f"Classically Weak / Deprecated Algorithm Detected: {algo_name}"
                    description = (
                        f"Evidence in '{filename}' shows use of {algo_name} ({crypto_category}). "
                        f"This is a classically weak or deprecated algorithm/protocol version -- not "
                        f"specifically a quantum-computing concern, but already considered broken or "
                        f"unsafe against today's classical attacks and should be retired regardless of "
                        f"the organization's PQC migration timeline."
                    )
                    remediation = _REMEDIATION_WEAK
                else:  # SAFE
                    title = f"Quantum-Safe Algorithm Confirmed: {algo_name}"
                    description = (
                        f"Evidence in '{filename}' shows use of {algo_name} ({crypto_category}). "
                        f"This algorithm is considered quantum-resistant against currently known "
                        f"quantum attacks (Grover's algorithm only provides a quadratic speed-up "
                        f"against symmetric/hash primitives of this size, and NIST-selected PQC "
                        f"algorithms are designed to resist Shor's algorithm entirely)."
                    )
                    remediation = _REMEDIATION_SAFE

                finding = Finding(
                    title=title,
                    severity=severity,
                    target=asset_ctx,
                    description=description,
                    remediation=remediation,
                    evidence=evidence_line,
                    plugin_id=f"PQC-{rule_id}",
                    source_tool="PQC-Scan",
                )
                finding.asset_name = asset_ctx
                # Auto-classify the asset category from filename + context window.
                _cat_window = content[max(0, start - 400): min(len(content), end + 400)]
                finding.asset_category = _classify_asset_category(asset_ctx, filename, _cat_window)
                finding.quantum_status = quantum_status

                # Enhancement B/D infrastructure: best-effort asset_name
                # enrichment, ONLY when Phase-1's stricter _find_asset_context()
                # found no real "Host:"/"Target:"-style heading and fell back
                # to the bare filename -- never overrides a genuine Phase-1
                # match. Narrative/architecture-diagram evidence (this is the
                # exact style Enhancements B and D are meant to read) labels
                # blocks with plain heading lines instead, which the broader
                # _find_block_heading_context() heuristic picks up.
                if asset_ctx == filename:
                    block_heading = _find_block_heading_context(content, start)
                    if block_heading:
                        finding.asset_name = block_heading

                # Enhancement 1: CA / Key / Protocol layer classification (best-effort).
                crypto_layer = _classify_crypto_layer(content, start, end)
                if crypto_layer == "CA":
                    finding.ca_algorithm = algo_name
                elif crypto_layer == "KEY":
                    finding.key_algorithm = algo_name
                elif crypto_layer == "PROTOCOL":
                    finding.protocol_version = algo_name

                # Enhancement 2: exposure context (severity already escalated above).
                finding.exposure_context = exposure_context

                # Enhancement 3: nearby port reference (best-effort, never fabricated).
                finding.port = _find_port(content, start, end)

                # Enhancement 4: prod/non-prod environment tag (informational only).
                finding.environment = _classify_environment(content, start, asset_ctx, filename)

                # Enhancement C: OEM/vendor PQC readiness matrix lookup (best-effort).
                oem_product, _oem_vendor, oem_status = _match_oem_readiness(content, filename)
                finding.oem_product = oem_product
                finding.oem_readiness_status = oem_status

                if finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    actionable_findings.append(finding)
                else:
                    info_findings.append(finding)

        if not actionable_findings and not info_findings:
            return [], []

        # Enhancement D: dependency-chain mapping (evidence-stated only, never
        # inferred). Only VULNERABLE findings participate -- SAFE/WEAK assets
        # aren't part of the "migration dependency" concept this models.
        chains = _parse_dependency_chains(content)
        if chains:
            vulnerable_findings = [f for f in actionable_findings if f.quantum_status == "VULNERABLE"]
            for f in vulnerable_findings:
                asset_lower = (f.asset_name or "").lower()
                if not asset_lower:
                    continue

                matched_chain = None
                matched_index = -1
                for chain in chains:
                    for idx, node in enumerate(chain):
                        node_lower = node.lower()
                        if node_lower in asset_lower or asset_lower in node_lower:
                            matched_chain, matched_index = chain, idx
                            break
                    if matched_chain:
                        break
                if matched_chain is None:
                    continue

                f.dependency_chain = " -> ".join(matched_chain)

                # A "migration dependency" exists when this asset shares an
                # explicit chain with at least one OTHER asset that also has
                # its own VULNERABLE finding elsewhere in this file --
                # direction-agnostic (checked against every other node in the
                # chain, not just strictly-downstream ones), since fixing one
                # crypto asset in a stated dependency chain has migration-
                # sequencing implications for every other vulnerable asset in
                # that same chain regardless of traffic direction.
                for other_idx, other_node in enumerate(matched_chain):
                    if other_idx == matched_index:
                        continue
                    other_node_lower = other_node.lower()
                    for other_f in vulnerable_findings:
                        if other_f is f:
                            continue
                        other_asset_lower = (other_f.asset_name or "").lower()
                        if other_asset_lower and (
                            other_node_lower in other_asset_lower or other_asset_lower in other_node_lower
                        ):
                            f.migration_dependency_flag = True
                            break
                    if f.migration_dependency_flag:
                        break

        map_pqc_findings_list(actionable_findings)
        map_pqc_findings_list(info_findings)

        print(
            f"[PQC PARSER] Extracted {len(actionable_findings)} actionable + "
            f"{len(info_findings)} informational finding(s) from '{filename}'.",
            flush=True
        )
        return actionable_findings, info_findings
