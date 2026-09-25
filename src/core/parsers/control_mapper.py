# -*- coding: utf-8 -*-
import re
from typing import List, Optional
from .finding_schema import Finding

# CWE to OWASP Top 10 (2021): the "List of Mapped CWEs" OWASP publishes for
# each category, in full. The table used to hold 30 of them, so a finding
# whose report named the CWE was classified by keywords instead: Burp's XXE
# (CWE-611, A05) filed as Injection, open redirection (CWE-601, A01) and
# "TLS cookie without secure flag" (CWE-614, A05) as Security Misconfiguration
# and Cryptographic Failures, and CWE-200 was held under A05 though OWASP
# lists it first under A01.
#
# Two entries are not in OWASP's lists and are kept as they were: CWE-693
# (protection mechanism failure) under A05, and CWE-259 under A02 -- OWASP
# names CWE-259 as a notable A02 weakness while listing it under A07.
CWE_TO_OWASP_MAP = {
    # A01:2021 Broken Access Control
    "CWE-22": "A01:2021 Broken Access Control", "CWE-23": "A01:2021 Broken Access Control",
    "CWE-35": "A01:2021 Broken Access Control", "CWE-59": "A01:2021 Broken Access Control",
    "CWE-200": "A01:2021 Broken Access Control", "CWE-201": "A01:2021 Broken Access Control",
    "CWE-219": "A01:2021 Broken Access Control", "CWE-264": "A01:2021 Broken Access Control",
    "CWE-275": "A01:2021 Broken Access Control", "CWE-276": "A01:2021 Broken Access Control",
    "CWE-284": "A01:2021 Broken Access Control", "CWE-285": "A01:2021 Broken Access Control",
    "CWE-352": "A01:2021 Broken Access Control", "CWE-359": "A01:2021 Broken Access Control",
    "CWE-377": "A01:2021 Broken Access Control", "CWE-402": "A01:2021 Broken Access Control",
    "CWE-425": "A01:2021 Broken Access Control", "CWE-441": "A01:2021 Broken Access Control",
    "CWE-497": "A01:2021 Broken Access Control", "CWE-538": "A01:2021 Broken Access Control",
    "CWE-540": "A01:2021 Broken Access Control", "CWE-548": "A01:2021 Broken Access Control",
    "CWE-552": "A01:2021 Broken Access Control", "CWE-566": "A01:2021 Broken Access Control",
    "CWE-601": "A01:2021 Broken Access Control", "CWE-639": "A01:2021 Broken Access Control",
    "CWE-651": "A01:2021 Broken Access Control", "CWE-668": "A01:2021 Broken Access Control",
    "CWE-706": "A01:2021 Broken Access Control", "CWE-862": "A01:2021 Broken Access Control",
    "CWE-863": "A01:2021 Broken Access Control", "CWE-913": "A01:2021 Broken Access Control",
    "CWE-922": "A01:2021 Broken Access Control", "CWE-1275": "A01:2021 Broken Access Control",

    # A02:2021 Cryptographic Failures
    "CWE-259": "A02:2021 Cryptographic Failures", "CWE-261": "A02:2021 Cryptographic Failures",
    "CWE-296": "A02:2021 Cryptographic Failures", "CWE-310": "A02:2021 Cryptographic Failures",
    "CWE-319": "A02:2021 Cryptographic Failures", "CWE-321": "A02:2021 Cryptographic Failures",
    "CWE-322": "A02:2021 Cryptographic Failures", "CWE-323": "A02:2021 Cryptographic Failures",
    "CWE-324": "A02:2021 Cryptographic Failures", "CWE-325": "A02:2021 Cryptographic Failures",
    "CWE-326": "A02:2021 Cryptographic Failures", "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-328": "A02:2021 Cryptographic Failures", "CWE-329": "A02:2021 Cryptographic Failures",
    "CWE-330": "A02:2021 Cryptographic Failures", "CWE-331": "A02:2021 Cryptographic Failures",
    "CWE-335": "A02:2021 Cryptographic Failures", "CWE-336": "A02:2021 Cryptographic Failures",
    "CWE-337": "A02:2021 Cryptographic Failures", "CWE-338": "A02:2021 Cryptographic Failures",
    "CWE-340": "A02:2021 Cryptographic Failures", "CWE-347": "A02:2021 Cryptographic Failures",
    "CWE-523": "A02:2021 Cryptographic Failures", "CWE-720": "A02:2021 Cryptographic Failures",
    "CWE-757": "A02:2021 Cryptographic Failures", "CWE-759": "A02:2021 Cryptographic Failures",
    "CWE-760": "A02:2021 Cryptographic Failures", "CWE-780": "A02:2021 Cryptographic Failures",
    "CWE-818": "A02:2021 Cryptographic Failures", "CWE-916": "A02:2021 Cryptographic Failures",

    # A03:2021 Injection
    "CWE-20": "A03:2021 Injection", "CWE-74": "A03:2021 Injection",
    "CWE-75": "A03:2021 Injection", "CWE-77": "A03:2021 Injection",
    "CWE-78": "A03:2021 Injection", "CWE-79": "A03:2021 Injection",
    "CWE-80": "A03:2021 Injection", "CWE-83": "A03:2021 Injection",
    "CWE-87": "A03:2021 Injection", "CWE-88": "A03:2021 Injection",
    "CWE-89": "A03:2021 Injection", "CWE-90": "A03:2021 Injection",
    "CWE-91": "A03:2021 Injection", "CWE-93": "A03:2021 Injection",
    "CWE-94": "A03:2021 Injection", "CWE-95": "A03:2021 Injection",
    "CWE-96": "A03:2021 Injection", "CWE-97": "A03:2021 Injection",
    "CWE-98": "A03:2021 Injection", "CWE-99": "A03:2021 Injection",
    "CWE-100": "A03:2021 Injection", "CWE-113": "A03:2021 Injection",
    "CWE-116": "A03:2021 Injection", "CWE-138": "A03:2021 Injection",
    "CWE-184": "A03:2021 Injection", "CWE-470": "A03:2021 Injection",
    "CWE-471": "A03:2021 Injection", "CWE-564": "A03:2021 Injection",
    "CWE-610": "A03:2021 Injection", "CWE-643": "A03:2021 Injection",
    "CWE-644": "A03:2021 Injection", "CWE-652": "A03:2021 Injection",
    "CWE-917": "A03:2021 Injection",

    # A04:2021 Insecure Design
    "CWE-73": "A04:2021 Insecure Design", "CWE-183": "A04:2021 Insecure Design",
    "CWE-209": "A04:2021 Insecure Design", "CWE-213": "A04:2021 Insecure Design",
    "CWE-235": "A04:2021 Insecure Design", "CWE-256": "A04:2021 Insecure Design",
    "CWE-257": "A04:2021 Insecure Design", "CWE-266": "A04:2021 Insecure Design",
    "CWE-269": "A04:2021 Insecure Design", "CWE-280": "A04:2021 Insecure Design",
    "CWE-311": "A04:2021 Insecure Design", "CWE-312": "A04:2021 Insecure Design",
    "CWE-313": "A04:2021 Insecure Design", "CWE-316": "A04:2021 Insecure Design",
    "CWE-419": "A04:2021 Insecure Design", "CWE-430": "A04:2021 Insecure Design",
    "CWE-434": "A04:2021 Insecure Design", "CWE-444": "A04:2021 Insecure Design",
    "CWE-451": "A04:2021 Insecure Design", "CWE-472": "A04:2021 Insecure Design",
    "CWE-501": "A04:2021 Insecure Design", "CWE-522": "A04:2021 Insecure Design",
    "CWE-525": "A04:2021 Insecure Design", "CWE-539": "A04:2021 Insecure Design",
    "CWE-579": "A04:2021 Insecure Design", "CWE-598": "A04:2021 Insecure Design",
    "CWE-602": "A04:2021 Insecure Design", "CWE-642": "A04:2021 Insecure Design",
    "CWE-646": "A04:2021 Insecure Design", "CWE-650": "A04:2021 Insecure Design",
    "CWE-653": "A04:2021 Insecure Design", "CWE-656": "A04:2021 Insecure Design",
    "CWE-657": "A04:2021 Insecure Design", "CWE-799": "A04:2021 Insecure Design",
    "CWE-807": "A04:2021 Insecure Design", "CWE-840": "A04:2021 Insecure Design",
    "CWE-841": "A04:2021 Insecure Design", "CWE-927": "A04:2021 Insecure Design",
    "CWE-1021": "A04:2021 Insecure Design", "CWE-1173": "A04:2021 Insecure Design",

    # A05:2021 Security Misconfiguration
    "CWE-2": "A05:2021 Security Misconfiguration",
    "CWE-11": "A05:2021 Security Misconfiguration",
    "CWE-13": "A05:2021 Security Misconfiguration",
    "CWE-15": "A05:2021 Security Misconfiguration",
    "CWE-16": "A05:2021 Security Misconfiguration",
    "CWE-260": "A05:2021 Security Misconfiguration",
    "CWE-315": "A05:2021 Security Misconfiguration",
    "CWE-520": "A05:2021 Security Misconfiguration",
    "CWE-526": "A05:2021 Security Misconfiguration",
    "CWE-537": "A05:2021 Security Misconfiguration",
    "CWE-541": "A05:2021 Security Misconfiguration",
    "CWE-547": "A05:2021 Security Misconfiguration",
    "CWE-611": "A05:2021 Security Misconfiguration",
    "CWE-614": "A05:2021 Security Misconfiguration",
    "CWE-693": "A05:2021 Security Misconfiguration",
    "CWE-756": "A05:2021 Security Misconfiguration",
    "CWE-776": "A05:2021 Security Misconfiguration",
    "CWE-942": "A05:2021 Security Misconfiguration",
    "CWE-1004": "A05:2021 Security Misconfiguration",
    "CWE-1032": "A05:2021 Security Misconfiguration",
    "CWE-1174": "A05:2021 Security Misconfiguration",

    # A06:2021 Vulnerable and Outdated Components
    "CWE-937": "A06:2021 Vulnerable and Outdated Components",
    "CWE-1035": "A06:2021 Vulnerable and Outdated Components",
    "CWE-1104": "A06:2021 Vulnerable and Outdated Components",

    # A07:2021 Identification & Auth Failures
    "CWE-255": "A07:2021 Identification & Auth Failures",
    "CWE-287": "A07:2021 Identification & Auth Failures",
    "CWE-288": "A07:2021 Identification & Auth Failures",
    "CWE-290": "A07:2021 Identification & Auth Failures",
    "CWE-294": "A07:2021 Identification & Auth Failures",
    "CWE-295": "A07:2021 Identification & Auth Failures",
    "CWE-297": "A07:2021 Identification & Auth Failures",
    "CWE-300": "A07:2021 Identification & Auth Failures",
    "CWE-302": "A07:2021 Identification & Auth Failures",
    "CWE-304": "A07:2021 Identification & Auth Failures",
    "CWE-306": "A07:2021 Identification & Auth Failures",
    "CWE-307": "A07:2021 Identification & Auth Failures",
    "CWE-346": "A07:2021 Identification & Auth Failures",
    "CWE-384": "A07:2021 Identification & Auth Failures",
    "CWE-521": "A07:2021 Identification & Auth Failures",
    "CWE-613": "A07:2021 Identification & Auth Failures",
    "CWE-620": "A07:2021 Identification & Auth Failures",
    "CWE-640": "A07:2021 Identification & Auth Failures",
    "CWE-798": "A07:2021 Identification & Auth Failures",
    "CWE-940": "A07:2021 Identification & Auth Failures",
    "CWE-1216": "A07:2021 Identification & Auth Failures",

    # A08:2021 Software and Data Integrity Failures
    "CWE-345": "A08:2021 Software and Data Integrity Failures",
    "CWE-353": "A08:2021 Software and Data Integrity Failures",
    "CWE-426": "A08:2021 Software and Data Integrity Failures",
    "CWE-494": "A08:2021 Software and Data Integrity Failures",
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
    "CWE-565": "A08:2021 Software and Data Integrity Failures",
    "CWE-784": "A08:2021 Software and Data Integrity Failures",
    "CWE-829": "A08:2021 Software and Data Integrity Failures",
    "CWE-830": "A08:2021 Software and Data Integrity Failures",
    "CWE-915": "A08:2021 Software and Data Integrity Failures",

    # A09:2021 Security Logging & Monitoring Failures
    "CWE-117": "A09:2021 Security Logging & Monitoring Failures",
    "CWE-223": "A09:2021 Security Logging & Monitoring Failures",
    "CWE-532": "A09:2021 Security Logging & Monitoring Failures",
    "CWE-778": "A09:2021 Security Logging & Monitoring Failures",

    # A10:2021 Server-Side Request Forgery (SSRF)
    "CWE-918": "A10:2021 Server-Side Request Forgery (SSRF)",
}

def get_dedup_key(title: str, target: str, cve_list: Optional[List[str]] = None, plugin_id: Optional[str] = None) -> str:
    """
    CVE-First, Plugin-ID-fallback, Title-last Deduplication Strategy.
    Prevents accidentally merging distinct vulnerabilities (e.g. Notepad++ < 8.8.2 vs < 8.9.2).
    """
    t_clean = (target or "").strip().lower()
    if cve_list and len(cve_list) > 0:
        cve_str = ",".join(sorted([str(c).upper().strip() for c in cve_list if c]))
        if cve_str:
            return f"cve:{cve_str}|target:{t_clean}"
    if plugin_id and str(plugin_id).strip():
        return f"plugin:{str(plugin_id).strip()}|target:{t_clean}"
    return f"title:{(title or '').strip().lower()}|target:{t_clean}"

# Ordered OWASP Top 10 (2021) keyword rules -- first match wins, so the more
# specific vulnerability classes are listed before the broader ones. Applied to the
# finding title first and only then to title+description (see map_finding_to_owasp).
_OWASP_KEYWORD_RULES = (
    ("A03:2021 Injection", (
        "xss", "cross-site scripting", "cross site scripting", "sqli", "sql injection",
        "command injection", "os command", "ldap injection", "xpath injection",
        "code injection", "xxe", "xml external entity", "template injection",
    )),
    ("A10:2021 Server-Side Request Forgery (SSRF)", (
        "ssrf", "server-side request forgery", "server side request forgery",
    )),
    ("A01:2021 Broken Access Control", (
        "access control", "privilege escalation", "directory traversal",
        "path traversal", "idor", "insecure direct object", "cors",
        "forced browsing", "unauthorized access",
    )),
    ("A02:2021 Cryptographic Failures", (
        "weak cipher", "weak encryption", "ssl", "tls", "hsts", "plaintext",
        "cleartext", "unencrypted", "self-signed", "certificate expired",
        "sweet32", "poodle", "beast", "lucky13", "deprecated algorithm",
        # "Cryptographic Failure" and "Missing Encryption of Sensitive Data"
        # named their class plainly and matched none of the words above.
        "cryptographic", "encryption",
    )),
    ("A06:2021 Vulnerable and Outdated Components", (
        "outdated", "end of life", "end-of-life", "eol", "unpatched", "obsolete",
        "unsupported version", "known vulnerable",
        "vulnerable javascript", "javascript dependency", "vulnerable dependency",
        "vulnerable component", "vulnerable library",
    )),
    ("A07:2021 Identification & Auth Failures", (
        "authentication", "password", "session", "credential", "jwt",
        "brute force", "mfa", "2fa", "multi-factor",
    )),
)


def map_finding_to_owasp(cwe_id: Optional[str], title: str, desc: str) -> str:
    """
    100% Deterministic OWASP Top 10 Mapper via static CWE tables.
    """
    if cwe_id:
        cwe_clean = f"CWE-{re.sub(r'[^0-9]', '', str(cwe_id))}"
        if cwe_clean in CWE_TO_OWASP_MAP:
            return CWE_TO_OWASP_MAP[cwe_clean]
            
    # No CWE. In practice that is the normal case, not the exception: none of the
    # real scanner exports in VAPT/ carries a single CWE id, so this keyword pass
    # -- not the table above -- is what actually classifies production findings.
    #
    # It therefore has to be right about two things it previously got wrong.
    #
    # 1) The TITLE names the vulnerability; the description explains how it is
    #    exploited, and routinely names OTHER vulnerability classes while doing so.
    #    Searching both as one blob let that prose win. Confirmed on a real Burp
    #    export: "Missing Secure/HttpOnly Flags on Session Cookies" was classified
    #    A03 Injection because its description reads "Attackers can steal these
    #    cookies via Cross-Site Scripting (XSS) or man-in-the-middle attacks".
    #    Remediation text does the same. So: classify on the title, and consult the
    #    description only when the title carries no signal at all.
    #
    # 2) Scanners spell things out. "xss" alone missed "Cross-site scripting
    #    (DOM-based)", which then fell through every branch to the A05 default --
    #    so two XSS findings in one report landed in two different categories.
    #
    # "authentication" replaces the old bare "auth", which also matched "author"
    # and "authorized" in unrelated findings.
    for category, keywords in _OWASP_KEYWORD_RULES:
        if any(k in (title or "").lower() for k in keywords):
            return category

    combined = f"{(title or '').lower()} {(desc or '').lower()}"
    for category, keywords in _OWASP_KEYWORD_RULES:
        if any(k in combined for k in keywords):
            return category

    return "A05:2021 Security Misconfiguration"

def map_finding_to_control(finding: Finding) -> str:
    """
    Centralized 100% Deterministic VAPT control mapper.
    Assigns a VAPT control ID (VAPT-1 .. VAPT-15) based on finding metadata,
    title, CVEs, and description. ZERO LLM dependency for category mapping.
    """
    title_lower = (finding.title or "").lower()
    desc_lower = (finding.description or "").lower()
    ev_lower = (finding.evidence or "").lower()
    combined = f"{title_lower} {desc_lower} {ev_lower}"

    # 1. Specific technical vulnerability classifications
    if any(k in combined for k in ("rce", "remote code execution", "directory traversal", "winrar", "buffer overflow")):
        return "VAPT-5"

    if any(k in combined for k in ("privilege escalation", "privesc", "uac bypass", "sudo")):
        return "VAPT-7"

    if any(k in combined for k in ("weak cipher", "ssl", "tls", "rc4", "3des", "cbc", "plaintext", "unencrypted", "default credentials", "default password")):
        return "VAPT-14"

    if any(k in combined for k in ("web", "http", "https", "xss", "sqli", "csrf", "hsts", "cookie", "apache", "nginx", "iis", "owasp")):
        return "VAPT-4"

    if any(k in combined for k in ("patch", "outdated", "update required", "installed version", "fixed version", "end of life", "eol")):
        return "VAPT-12"

    if any(k in combined for k in ("api", "rest", "graphql", "jwt", "swagger", "openapi")):
        return "VAPT-10"

    if any(k in combined for k in ("wireless", "wifi", "wpa", "802.11", "bluetooth")):
        return "VAPT-9"

    if any(k in combined for k in ("phishing", "spf", "dkim", "dmarc", "social engineering")):
        return "VAPT-8"

    if any(k in combined for k in ("reconnaissance", "osint", "whois", "dns zone")):
        return "VAPT-2"

    if any(k in combined for k in ("firewall", "segmentation", "filtered port")):
        return "VAPT-13"

    # Default fallback for network scanner findings
    return "VAPT-3"


def map_finding_to_pqc_control(finding: Finding) -> str:
    """
    Centralized 100% Deterministic PQC (Post-Quantum Cryptography Readiness)
    control mapper. Assigns a PQC control ID (PQC-1 .. PQC-12) based on finding
    title/description/evidence keywords. ZERO LLM dependency.

    Separate from map_finding_to_control() (VAPT-1..15-specific) -- PQC findings
    must never be routed through that function or they'd get mis-mapped to
    VAPT control IDs. Only PQC-1..PQC-9 (technical evidence controls) are
    reachable from a scanned finding here; PQC-10/11/12 are governance/
    process controls (remediation tracker, migration roadmap, final CBOM/QBOM
    sign-off) that a raw algorithm detection can't determine on its own --
    same as how several VAPT-* process controls (VAPT-1, VAPT-8, VAPT-15, etc.)
    are never reached by map_finding_to_control() either.
    """
    title_lower = (finding.title or "").lower()
    desc_lower = (finding.description or "").lower()
    ev_lower = (finding.evidence or "").lower()
    combined = f"{title_lower} {desc_lower} {ev_lower}"

    # Narrower/more specific categories are checked before the broad TLS/SSL
    # bucket, mirroring map_finding_to_control()'s own "specific before generic"
    # ordering -- otherwise an SSH or IPSec finding that happens to also mention
    # "TLS" in passing would get bucketed under the generic TLS/SSL control.
    if any(k in combined for k in ("ssh", "sshd", "openssh")):
        return "PQC-3"

    if any(k in combined for k in ("ipsec", "vpn", " ike ", "ikev1", "ikev2", "phase 1", "phase 2", "phase1", "phase2")):
        return "PQC-4"

    if any(k in combined for k in ("certificate", "x.509", "x509", "pki", "csr", "certificate authority", " ca ")):
        return "PQC-5"

    if any(k in combined for k in ("database", "tde", "transparent data encryption", "db encryption", "at-rest", "at rest", "data at rest")):
        return "PQC-6"

    if any(k in combined for k in ("library", "dependency", "package", "sdk", "openssl version", "crypto library", "cryptographic library")):
        return "PQC-7"

    if any(k in combined for k in ("hsm", "kms", "key management", "key vault", "keystore", "key store")):
        return "PQC-8"

    if any(k in combined for k in ("code signing", "code-signing", "firmware signing", "firmware", "authenticode")):
        return "PQC-9"

    if any(k in combined for k in ("tls", "ssl", "cipher suite", "https", "handshake")):
        return "PQC-2"

    # Default fallback: cryptographic asset inventory
    return "PQC-1"


# ══════════════════════════════════════════════════════════════════════════════
# RISK CATEGORY TAXONOMY  (100% offline — static deterministic lookup)
# ══════════════════════════════════════════════════════════════════════════════

# Maps OWASP Top 10 codes to human-readable risk categories
_OWASP_TO_CATEGORY = {
    "A01": "Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Authentication Failures",
    "A08": "Data Integrity Failures",
    "A09": "Logging & Monitoring",
    "A10": "SSRF",
}

def map_finding_to_risk_category(finding: Finding) -> str:
    """
    Maps a Finding to a human-readable Risk Category using:
    1. CWE → OWASP Top 10 static lookup
    2. Title/description keyword fallback
    Returns a category string like 'Injection', 'Access Control', etc.
    100% offline — no network calls.
    """
    # Try CWE-based OWASP mapping first
    cwe_id = None
    # Extract CWE from CVE list or evidence
    combined = f"{(finding.title or '').lower()} {(finding.description or '').lower()} {(finding.evidence or '').lower()}"
    cwe_match = re.search(r'CWE-(\d+)', combined, re.IGNORECASE)
    if cwe_match:
        cwe_id = cwe_match.group(0).upper()

    # The CWEs the parser extracted, in the order the report gave them. They
    # used to be ignored here in favour of a search of the free text, which for
    # most scanner exports holds no CWE at all -- so classification fell to the
    # keyword pass below, which reads the DESCRIPTION. On a real Burp report a
    # "Vulnerable JavaScript dependency" (CWE-1104, OWASP A06) was filed under
    # Injection because the CVE it quotes describes a cross-site scripting bug.
    _candidates = [cwe_id] if cwe_id else []
    _candidates += [str(c).upper() for c in (finding.cve_list or [])
                    if str(c).upper().startswith("CWE-") and str(c).upper() not in _candidates]
    for _cwe in _candidates:
        owasp = CWE_TO_OWASP_MAP.get(_cwe, "")
        if owasp:
            # Extract A0x prefix to map to category
            code = owasp[:3]
            if code in _OWASP_TO_CATEGORY:
                return _OWASP_TO_CATEGORY[code]

    # Use the existing OWASP mapper as fallback
    owasp_str = map_finding_to_owasp(cwe_id, finding.title, finding.description)
    if owasp_str:
        code = owasp_str[:3]
        if code in _OWASP_TO_CATEGORY:
            return _OWASP_TO_CATEGORY[code]

    # Final keyword-based fallback
    if any(k in combined for k in ("xss", "sqli", "sql injection", "command injection", "ldap injection", "scripting", "injection")):
        return "Injection"
    if any(k in combined for k in ("access control", "privilege escalation", "directory traversal", "cors", "idor", "unauthorized")):
        return "Access Control"
    if any(k in combined for k in ("weak cipher", "ssl", "tls", "plaintext", "unencrypted", "hsts", "crypto")):
        return "Cryptographic Failures"
    if any(k in combined for k in ("auth", "password", "session", "credential", "jwt", "login")):
        return "Authentication Failures"
    if any(k in combined for k in ("ssrf", "server-side request forgery")):
        return "SSRF"
    if any(k in combined for k in ("patch", "update", "outdated", "eol", "end of life")):
        return "Vulnerable Components"
    if any(k in combined for k in ("network", "port", "tcp", "udp", "firewall", "nmap", "open port")):
        return "Network Security"
    if any(k in combined for k in ("log", "monitoring", "audit trail")):
        return "Logging & Monitoring"

    return "Security Misconfiguration"



# ══════════════════════════════════════════════════════════════════════════════
# CIA IMPACT & PII EXPOSURE EVALUATOR  (100% offline — regex-based)
# ══════════════════════════════════════════════════════════════════════════════

# PII / sensitive data patterns for the "⚠ PII EXPOSURE DETECTED" report flag.
# Deliberately does NOT include IPv4 -- a VAPT finding's target host IP is the
# report's actual content, not personally-identifying data, and every finding
# mentions one; flagging on it made the badge fire on ~100% of findings and
# stop carrying any signal. Matches the same IP-is-not-PII call already made
# for VAPT export redaction (src/core/report_exporter.py, redact_pii(redact_ip=False)).
_PII_PATTERNS = [
    # Email: require word chars on both sides of '@', exclude crypto algo identifiers
    # (e.g. sntrup761x25519-sha512@openssh.com is a KEX algo name, not a personal email).
    # Guard: must start with >=2 plain word chars (letters/digits only before any special),
    # and the local part must NOT look like a crypto/hash string (all-hex or digit+hyphen heavy).
    re.compile(
        r'(?<![\w@])'
        r'(?!(?:[0-9a-f]{8,}|[\w\d]+-sha[0-9]+|sntrup|mlkem|kyber|dilithium|sphincs|falcon)[^\s]*@)'
        r'[a-zA-Z0-9][\w.+\-]{1,}@[\w\-]+\.(?:[a-zA-Z]{2,})',
        re.IGNORECASE
    ),   # Email (with crypto-algo false-positive guard)
    re.compile(r'(?:password|passwd|pwd|secret|api[_\-]?key|token|credential|private[_\-]?key)\s*[:=]\s*\S+', re.IGNORECASE),  # Credentials
    re.compile(r'(?:ssn|social\s+security|credit\s+card|card\s+number|pan\s+number|aadhaar)', re.IGNORECASE),  # PII identifiers
]

# ── Keyword fallback, used only when no CVSS vector is available ────────────
# Matched on word boundaries, never as bare substrings. The previous plain
# `k in text` form meant "dos" matched inside any word containing it -- and
# because a finding's description carries raw HTTP captures, base64 session
# cookies (AWSALBCORS=a9a62VnhJoODUmGeknITOV4w...) hit it routinely and marked
# A:HIGH on findings with no availability impact at all. "token" and "sensitive"
# had the same exposure against ordinary response headers.
_C_HIGH_KEYWORDS = (
    "information disclosure", "data leak", "sensitive", "credential",
    "password", "token", "private key", "directory listing",
    "source code", "backup file", "database dump", "pii",
    # Classes that were entirely absent, so every one of them reported
    # C:NONE regardless of severity:
    "ssrf", "server-side request forgery", "external service interaction",
    "idor", "insecure direct object", "broken access control",
    "path traversal", "directory traversal", "local file inclusion", "lfi",
    "xxe", "xml external entity", "arbitrary file read",
    # Cross-site scripting was listed only under integrity, so the textbook
    # payload -- stealing document.cookie and posting it to the attacker --
    # reported C:NONE. Session theft is a confidentiality loss.
    "xss", "cross-site scripting", "cross site scripting",
    "session hijack", "cookie theft", "document.cookie", "session token",
)
_C_MEDIUM_KEYWORDS = (
    "version disclosure", "banner", "stack trace", "error message",
    "server header", "configuration",
)
_I_HIGH_KEYWORDS = (
    "injection", "sqli", "xss", "csrf", "command injection",
    "code execution", "rce", "file upload", "deserialization",
    # Missing classes, as above:
    "ssti", "template injection", "broken access control",
    "privilege escalation", "arbitrary file write", "mass assignment",
    # The spelled-out forms. The table carried the acronyms only, so a finding
    # whose text says "Cross-Site Scripting" rather than "XSS" -- which is what
    # the visual-PoC describer now writes -- matched confidentiality but not
    # integrity, and reported I:NONE on a scripting flaw.
    "cross-site scripting", "cross site scripting",
    "cross-site request forgery", "cross site request forgery",
    "sql injection", "os command injection",
)
_I_MEDIUM_KEYWORDS = ("open redirect", "clickjacking", "header injection")
_A_HIGH_KEYWORDS = (
    "denial of service", "dos", "ddos", "buffer overflow",
    "resource exhaustion", "crash", "memory corruption",
)


def _kw_hit(text: str, keywords) -> bool:
    """True when any keyword occurs in text as a whole word/phrase.

    Word-boundary anchored so short tokens ("dos", "rce", "lfi", "xss") cannot
    match inside unrelated strings -- see the note above the keyword tables.
    """
    if not text:
        return False
    for kw in keywords:
        if re.search(r'(?<![a-z0-9])' + re.escape(kw) + r'(?![a-z0-9])', text):
            return True
    return False


_CVSS_METRIC_RE = re.compile(r'\bC:([NLH])\/I:([NLH])\/A:([NLH])\b', re.IGNORECASE)
_CVSS_METRIC_NAMES = {"N": "NONE", "L": "LOW", "H": "HIGH"}


def _cia_from_cvss_vector(vector: str):
    """Reads the C/I/A metrics straight out of a CVSS 3.1 vector string.

    Returns (c, i, a) as display words, or None when the vector is absent or
    malformed -- in which case the caller falls back to keyword inference.
    """
    if not vector:
        return None
    m = _CVSS_METRIC_RE.search(vector)
    if not m:
        return None
    return tuple(_CVSS_METRIC_NAMES[g.upper()] for g in m.groups())


def evaluate_cia_and_pii_impact(finding: Finding) -> tuple:
    """
    Evaluates CIA (Confidentiality, Integrity, Availability) impact and
    PII exposure for a Finding based on its content.
    Returns (cia_impact_str, is_pii_exposed).
    100% offline — uses local regex patterns only.
    """
    combined = f"{finding.title or ''} {finding.description or ''} {finding.evidence or ''} {finding.remediation or ''}"

    # ── PII Exposure Detection ──
    # PQC-Scan findings come from configuration files (TLS/SSH/IPSec config exports)
    # that never contain personal data -- skip PII detection to avoid false positives
    # (e.g. SSH KEX algo strings like sntrup761x25519-sha512@openssh.com matching email regex).
    is_pii = False
    if getattr(finding, "source_tool", "") != "PQC-Scan":
        for pattern in _PII_PATTERNS:
            if pattern.search(combined):
                is_pii = True
                break

    # ── CIA Impact Assessment ──
    combined_lower = combined.lower()
    c_impact = "NONE"
    i_impact = "NONE"
    a_impact = "NONE"

    # ── PQC / Quantum-specific CIA override ──────────────────────────────────
    # ONLY applied when the finding actually came from the PQC scanner
    # (source_tool == "PQC-Scan") OR already has quantum_status set.
    # Must NOT fire on ISO/VAPT findings that merely mention "RSA" or "ECDSA"
    # in evidence -- those use the generic CIA logic below.
    # Rationale: quantum-vulnerable algorithms break confidentiality (HNDL: harvest
    # now, decrypt later) and integrity (signature forgery). Availability is not
    # directly impacted by algorithm weakness alone.
    _is_pqc_finding = (
        getattr(finding, "source_tool", "") == "PQC-Scan"
        or bool(getattr(finding, "quantum_status", ""))
    )
    if _is_pqc_finding:
        c_impact = "HIGH"   # HNDL: data captured today decrypted post-Q-day
        i_impact = "HIGH"   # Signature forgery: ECC/RSA signatures are breakable
        # a_impact stays NONE — algorithm weakness alone doesn't cause DoS

    # ── CVSS vector is authoritative when the parser produced one ────────────
    # The keyword rules below are a last resort, not the primary source. Every
    # scanner parser already emits a CVSS 3.1 vector whose C/I/A metrics come
    # from the scanner's own classification, and re-deriving impact by keyword
    # produced results that contradicted it: an SSRF finding scored High was
    # displayed as "C:NONE | I:NONE | A:NONE", a combination that scores 0.0
    # under CVSS 3.1 and so cannot coexist with a High rating. Two independent
    # sources of truth for the same fact is the defect; the vector wins.
    _vector_cia = _cia_from_cvss_vector(getattr(finding, "cvss_vector", "") or "")
    if _vector_cia:
        v_c, v_i, v_a = _vector_cia
        # PQC's own override above is domain knowledge the vector doesn't carry,
        # so it is preserved where it already raised a metric.
        c_impact = v_c if c_impact == "NONE" else c_impact
        i_impact = v_i if i_impact == "NONE" else i_impact
        a_impact = v_a
        if is_pii:
            c_impact = "Confidential (High - PII Data Present)"
        return f"C:{c_impact} | I:{i_impact} | A:{a_impact}", is_pii

    # Confidentiality indicators (generic — only applied if not already set by PQC block)
    if c_impact == "NONE":
        if is_pii or _kw_hit(combined_lower, _C_HIGH_KEYWORDS):
            c_impact = "HIGH"
        elif _kw_hit(combined_lower, _C_MEDIUM_KEYWORDS):
            c_impact = "MEDIUM"

    # Integrity indicators (generic — only applied if not already set by PQC block)
    if i_impact == "NONE":
        if _kw_hit(combined_lower, _I_HIGH_KEYWORDS):
            i_impact = "HIGH"
        elif _kw_hit(combined_lower, _I_MEDIUM_KEYWORDS):
            i_impact = "MEDIUM"

    # Availability indicators
    if _kw_hit(combined_lower, _A_HIGH_KEYWORDS):
        a_impact = "HIGH"
    elif any(k in combined_lower for k in (
        "rate limit", "timeout", "slow"
    )):
        a_impact = "MEDIUM"

    if is_pii:
        c_impact = "Confidential (High - PII Data Present)"

    # "C:NONE | I:NONE | A:NONE" asserts that the finding has no impact at all.
    # Reaching here with all three still NONE means the opposite: no CVSS vector
    # was supplied and no keyword matched, so nothing was established either way.
    # Printing it as NONE turns "not determined" into "determined to be harmless",
    # which an auditor may reasonably act on by deprioritising a live finding.
    #
    # It is also self-contradictory on any finding that carries a real severity:
    # C:N/I:N/A:N scores 0.0 under CVSS 3.1 and cannot coexist with a High
    # rating -- the same contradiction already noted above for SSRF, where the
    # fix was to let the vector win. There is no vector here to win, so the
    # honest answer is to say so.
    #
    # It happens most often on findings recovered from a screenshot by OCR,
    # where the class name survives imperfectly ("Stored XSS]" read as "XSSI")
    # and no keyword can match, which is precisely when a confident "no impact"
    # is least warranted.
    if c_impact == "NONE" and i_impact == "NONE" and a_impact == "NONE":
        _sev = str(getattr(finding, "severity", "") or "").upper()
        if _sev and "INFO" not in _sev:
            return "Not determined - requires auditor assessment", is_pii

    cia_str = f"C:{c_impact} | I:{i_impact} | A:{a_impact}"
    return cia_str, is_pii


# ══════════════════════════════════════════════════════════════════════════════
# ACTIONABLE DEVELOPER REMEDIATION ENGINE  (100% offline — template-based)
# ══════════════════════════════════════════════════════════════════════════════

_REMEDIATION_TEMPLATES = {
    "sql injection": "Use parameterized queries (prepared statements) instead of string concatenation. Example: `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`. Apply input validation and use an ORM where possible.",
    "sqli": "Use parameterized queries (prepared statements) instead of string concatenation. Apply input validation and use an ORM where possible.",
    "cross-site scripting": "Encode all user-supplied output using context-aware encoding (HTML entity, JavaScript, URL encoding). Implement Content-Security-Policy (CSP) headers. Use frameworks with auto-escaping (React, Angular).",
    "xss": "Encode all user-supplied output using context-aware encoding. Implement Content-Security-Policy (CSP) headers.",
    "csrf": "Implement anti-CSRF tokens (synchronizer token pattern) on all state-changing requests. Set `SameSite=Strict` or `SameSite=Lax` on session cookies.",
    "hsts": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to all HTTPS responses. Ensure all resources load over HTTPS.",
    "ssl": "Upgrade to TLS 1.2+ minimum. Disable SSLv3, TLS 1.0, TLS 1.1. Use strong cipher suites (AES-GCM, ChaCha20). Renew expired certificates.",
    "tls": "Upgrade to TLS 1.2+ minimum. Disable weak protocols and cipher suites. Configure perfect forward secrecy (ECDHE).",
    "weak cipher": "Disable RC4, DES, 3DES, and CBC-mode ciphers. Configure server to prefer AES-256-GCM or ChaCha20-Poly1305.",
    "outdated": "Update the affected software/library to the latest stable version. Establish a patch management policy with regular update cycles.",
    "end of life": "Migrate to a supported version of the software immediately. Unsupported software receives no security patches.",
    "open redirect": "Validate and whitelist redirect URLs against a list of allowed domains. Never pass user-controlled URLs directly to redirect functions.",
    "directory traversal": "Sanitize file path inputs. Use a whitelist of allowed file paths. Never use user input directly in file system operations.",
    "command injection": "Avoid passing user input to shell commands. Use language-specific safe APIs (e.g., `subprocess.run()` with `shell=False`). Apply strict input validation.",
    "rce": "Patch the vulnerable component immediately. Isolate the affected service using network segmentation. Apply least-privilege execution context.",
    "default credentials": "Change all default usernames and passwords before deployment. Implement strong password policies and credential rotation.",
    "missing security headers": "Add security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Content-Security-Policy`, `Referrer-Policy: strict-origin-when-cross-origin`.",
    "clickjacking": "Set `X-Frame-Options: DENY` or `SAMEORIGIN`. Implement `Content-Security-Policy: frame-ancestors 'none'`.",
    "information disclosure": "Remove verbose error messages from production. Disable server version banners. Remove unnecessary HTTP response headers.",
    "ssrf": "Validate and whitelist allowed URLs/IP ranges. Block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x). Use a dedicated egress proxy.",
    "deserialization": "Avoid deserializing untrusted data. Use safe serialization formats (JSON) instead of native object serialization. Implement integrity checks.",
    "file upload": "Validate file types using content inspection (magic bytes), not just extensions. Store uploads outside the web root. Set size limits and scan for malware.",
    "privilege escalation": "Apply principle of least privilege. Validate authorization on every privileged action server-side. Use role-based access control (RBAC).",
    "brute force": "Implement account lockout or rate limiting after failed attempts. Use CAPTCHA. Enforce strong password policies and multi-factor authentication.",
    "path traversal": "Sanitize file path inputs. Use a whitelist of allowed file paths. Never use user input directly in file system operations.",
    "session fixation": "Regenerate the session ID immediately after login and on every privilege change. Never accept a session ID supplied by the client before authentication.",
    "cors": "Restrict `Access-Control-Allow-Origin` to an explicit whitelist of trusted domains. Never reflect the request's `Origin` header or use a wildcard (`*`) alongside `Access-Control-Allow-Credentials: true`.",
    "self-signed": "Replace the self-signed certificate with one issued by a trusted Certificate Authority. Configure automatic renewal (e.g. via ACME/Let's Encrypt) to prevent future expiry.",
    "self signed": "Replace the self-signed certificate with one issued by a trusted Certificate Authority. Configure automatic renewal (e.g. via ACME/Let's Encrypt) to prevent future expiry.",
    "md5": "Replace MD5/SHA-1 with a modern hashing algorithm (SHA-256 or better) for integrity checks, and a dedicated password-hashing function (bcrypt, scrypt, or Argon2) for credential storage.",
    "sha1": "Replace MD5/SHA-1 with a modern hashing algorithm (SHA-256 or better) for integrity checks, and a dedicated password-hashing function (bcrypt, scrypt, or Argon2) for credential storage.",
    "request smuggling": "Ensure front-end proxy and back-end server agree on request framing (Content-Length vs. Transfer-Encoding). Disable support for ambiguous/duplicate headers at the proxy layer.",
    "directory listing": "Disable directory browsing/auto-indexing at the web server configuration level (e.g. `Options -Indexes` in Apache, `autoindex off` in nginx).",
    "index of": "Disable directory browsing/auto-indexing at the web server configuration level (e.g. `Options -Indexes` in Apache, `autoindex off` in nginx).",
    "xml external entity": "Disable external entity and DTD processing in the XML parser (e.g. `XMLConstants.FEATURE_SECURE_PROCESSING` in Java, `resolve_entities=False` in lxml). Prefer a data format that doesn't support entities (JSON) where possible.",
    "xxe": "Disable external entity and DTD processing in the XML parser. Prefer a data format that doesn't support entities (JSON) where possible.",
    "insecure direct object reference": "Enforce server-side authorization checks on every object reference (verify the requesting user owns/may access the specific record ID), not just authentication. Use indirect reference maps or UUIDs instead of predictable sequential IDs.",
    "idor": "Enforce server-side authorization checks on every object reference, not just authentication. Use indirect reference maps or UUIDs instead of predictable sequential IDs.",
    "cleartext": "Enforce TLS for this service/protocol; disable the unencrypted listener entirely if a secure alternative exists (e.g. FTPS/SFTP instead of FTP, HTTPS instead of HTTP).",
    "unencrypted": "Enforce TLS for this service/protocol; disable the unencrypted listener entirely if a secure alternative exists.",
    "rate limit": "Implement request throttling per user/IP (e.g. token-bucket or sliding-window) on this endpoint, with a clear `429 Too Many Requests` response and `Retry-After` header.",
    # Keys below were added after a real Burp report's findings fell through to
    # a generic "apply the vendor-supplied patch" for flaws in the application's
    # own code. "open redirection" is here because the "open redirect" key is
    # matched on word boundaries and never matched Burp's spelling of the title.
    "open redirection": "Validate redirect targets against an allow-list of permitted destinations and never pass a URL taken from the request, the DOM (location, input values) or storage directly to a redirect or navigation sink.",
    "template injection": "Do not embed user input into client-side template regions (for AngularJS, anything inside an `ng-app` scope). Render untrusted values with `ng-bind`/text binding, or strip `{{ }}` expression syntax server-side before output. HTML-encoding alone does not prevent it. Upgrade off end-of-life AngularJS.",
    "prototype pollution": "Reject or strip `__proto__`, `constructor` and `prototype` keys when merging or cloning objects built from query strings, JSON or hash parameters. Create lookup objects with `Object.create(null)` or use `Map`, and freeze `Object.prototype` where the application allows.",
    "javascript dependency": "Upgrade the affected library to a release that fixes the listed CVEs (or replace an end-of-life library entirely). Add dependency scanning (e.g. `npm audit`, OWASP Dependency-Check) to the build so vulnerable versions are caught before release.",
    "vulnerable dependency": "Upgrade the affected component to a patched release. Add dependency scanning to the build so vulnerable versions are caught before release.",
    "httponly": "Set the `HttpOnly` attribute on every cookie that client-side script does not need to read -- always on session cookies -- so an injected script cannot read it.",
    "secure flag": "Set the `Secure` attribute on every cookie issued over HTTPS so the browser never sends it over plain HTTP.",
    "autocomplete": "Set `autocomplete=\"off\"` (or `\"new-password\"`) on password fields and on forms that collect credentials or other sensitive values.",
    "cacheable": "Return `Cache-Control: no-store` (and `Pragma: no-cache` for older clients) on responses containing sensitive or user-specific data.",
    "url override": "Disable support for `X-Original-URL` / `X-Rewrite-URL` in the framework or reverse proxy, or strip those headers at the edge before they reach the application.",
    "cryptographic failure": "Use current, vetted algorithms: store passwords with a slow salted KDF (Argon2id, bcrypt or scrypt) rather than a fast hash, use AES-GCM or ChaCha20-Poly1305 for encryption, and keep keys out of source code in a managed key store. Remove MD5, SHA-1, DES and ECB-mode usage.",
    "broken authentication": "Enforce authentication server-side on every protected endpoint, add multi-factor authentication for privileged accounts, lock or throttle repeated failed logins, and invalidate session tokens on logout and on privilege change.",
    "privilege escalation": "Enforce authorization server-side on every privileged function using role checks tied to the authenticated session -- never to a role, flag or ID supplied by the client -- and deny by default.",
    "input returned": "Reflected input is not exploitable on its own, but it is the precondition for XSS and injection: encode every reflected value for the context it is written into (HTML body, attribute, JavaScript, URL) and validate input against the format each parameter expects.",
}


# Developer guidance keyed by CWE, for findings whose title does not name the
# weakness in words a keyword template recognises -- which is common in reports
# that state the CWE and a short title. Consulted before the generic fallback,
# so a weakness class is never answered with "apply the vendor-supplied patch".
_CWE_REMEDIATION = {
    "CWE-269": _REMEDIATION_TEMPLATES["privilege escalation"],
    "CWE-285": _REMEDIATION_TEMPLATES["privilege escalation"],
    "CWE-639": _REMEDIATION_TEMPLATES["idor"],
    "CWE-287": _REMEDIATION_TEMPLATES["broken authentication"],
    "CWE-310": _REMEDIATION_TEMPLATES["cryptographic failure"],
    "CWE-326": _REMEDIATION_TEMPLATES["cryptographic failure"],
    "CWE-327": _REMEDIATION_TEMPLATES["cryptographic failure"],
    "CWE-328": _REMEDIATION_TEMPLATES["cryptographic failure"],
    "CWE-916": _REMEDIATION_TEMPLATES["cryptographic failure"],
    "CWE-311": "Encrypt this data in transit (TLS 1.2+) and, where it is stored, at rest with a managed key. Identify every field that carries personal or sensitive data and confirm none leaves the server unencrypted.",
    "CWE-319": _REMEDIATION_TEMPLATES["cleartext"],
    "CWE-602": "Re-implement every check that is currently enforced in the browser (validation, limits, business rules) on the server, and treat client-side checks as a usability aid only.",
    "CWE-770": "Apply server-side limits on how often and how much any client may request (per user and per IP), and cap the size of inputs and generated resources such as OTP or e-mail sends.",
    "CWE-601": _REMEDIATION_TEMPLATES["open redirection"],
    "CWE-1321": _REMEDIATION_TEMPLATES["prototype pollution"],
    "CWE-1104": _REMEDIATION_TEMPLATES["javascript dependency"],
    "CWE-614": _REMEDIATION_TEMPLATES["secure flag"],
    "CWE-1004": _REMEDIATION_TEMPLATES["httponly"],
    "CWE-524": _REMEDIATION_TEMPLATES["cacheable"],
    "CWE-525": _REMEDIATION_TEMPLATES["cacheable"],
    "CWE-523": _REMEDIATION_TEMPLATES["hsts"],
    "CWE-693": _REMEDIATION_TEMPLATES["clickjacking"],
    "CWE-1021": _REMEDIATION_TEMPLATES["clickjacking"],
    "CWE-436": _REMEDIATION_TEMPLATES["url override"],
    "CWE-89": _REMEDIATION_TEMPLATES["sql injection"],
    "CWE-79": _REMEDIATION_TEMPLATES["xss"],
    "CWE-611": _REMEDIATION_TEMPLATES["xxe"],
    "CWE-918": _REMEDIATION_TEMPLATES["ssrf"],
}

# ── MITRE CWE mitigations, for a finding whose source gave no remediation ─────
# src/core/knowledge/cwe_mitigations.json is built from MITRE's CWE list by
# scripts/build_cwe_mitigations.py (see there for the CWE Terms of Use notice
# it carries). A pentest report's findings table often has no remediation
# column at all, and the report then printed a template written here; MITRE's
# own mitigations for the finding's weakness are the better general guidance,
# and are labelled as such -- never as the tester's advice.

# A finding with no CWE of its own: its title, mapped conservatively. Only
# names that denote one weakness unambiguously; anything else keeps the
# existing fallback.
_TITLE_TO_CWE = (
    (r"\bsql\s*injection\b|\bsqli\b", "CWE-89"),
    (r"cross[- ]site scripting|\bxss\b", "CWE-79"),
    (r"cross[- ]site request forgery|\bcsrf\b", "CWE-352"),
    (r"server[- ]side request forgery|\bssrf\b|external service interaction", "CWE-918"),
    (r"xml external entit|\bxxe\b", "CWE-611"),
    (r"open redirect", "CWE-601"),
    (r"clickjacking|frameable response", "CWE-1021"),
    (r"os command injection|\bcommand injection\b", "CWE-78"),
    (r"template injection", "CWE-1336"),
    (r"path traversal|directory traversal|file path manipulation", "CWE-22"),
    (r"unrestricted file upload", "CWE-434"),
    (r"insecure direct object reference|\bidor\b", "CWE-639"),
    (r"privilege escalation", "CWE-269"),
    (r"broken authentication|authentication bypass", "CWE-287"),
    (r"default credential|default password", "CWE-1392"),
    (r"session fixation", "CWE-384"),
    (r"strict[- ]transport[- ]security|\bhsts\b", "CWE-523"),
    (r"without (?:the )?['\"]?secure['\"]? flag|secure flag (?:is )?not (?:set|configured)", "CWE-614"),
    (r"without (?:the )?['\"]?httponly['\"]? flag|httponly flag (?:is )?not (?:set|configured)", "CWE-1004"),
    # Transmission only: "Processes reveal plaintext passwords" is not CWE-319.
    (r"clear\s*text (?:data )?transmission|cleartext submission|unencrypted (?:connection|communication|channel)"
     r"|transmitted (?:in|over) (?:clear|plain)\s*text", "CWE-319"),
    (r"missing encryption", "CWE-311"),
    (r"insecure deserialization|unsafe deserialization", "CWE-502"),
    (r"prototype pollution", "CWE-1321"),
    (r"vulnerable (?:javascript )?(?:dependency|component|library)", "CWE-1395"),
)

# Phases whose mitigations are a fix, in the order they are preferred. "Testing"
# describes how to find the weakness, not how to remove it.
_FIX_PHASES = ("Implementation", "Operation", "System Configuration", "Patching and Maintenance",
               "Installation", "Architecture and Design", "Build and Compilation", "Integration")

_CWE_KB = None


def _cwe_kb() -> dict:
    global _CWE_KB
    if _CWE_KB is None:
        import json
        import os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "knowledge",
                            "cwe_mitigations.json")
        try:
            with open(path, encoding="utf-8") as fh:
                _CWE_KB = json.load(fh).get("cwe", {})
        except Exception:
            _CWE_KB = {}              # no knowledge file: the existing fallback applies
    return _CWE_KB


def _first_sentences(text: str, limit: int = 400) -> str:
    """MITRE's text without its "[REF-1482]" citations, cut at a sentence end."""
    text = str(text or "")
    # "According to [REF-1247], ..." -- the citation is the whole subject.
    text = re.sub(r"\bAccording to\s+(?:\[REF-\d+\][\s,and]*)+", "", text)
    text = re.sub(r"\s*\[REF-\d+\]", "", text)
    text = re.sub(r"\(\s*(?:see\s*)?\)", "", text)            # "(see [REF-1])" emptied
    text = re.sub(r"\s+([,.;:])", r"\1", text)
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    ends = [m.end() for m in re.finditer(r"[.!?](?=\s)", text) if m.end() <= limit]
    return text[:ends[-1]] if ends else text


def _pick_mitigations(mitigations, n: int = 3):
    """The first `n` of MITRE's mitigations that are fixes, in MITRE's order --
    MITRE lists the primary mitigation first (for SQL injection: a vetted
    framework, then structured queries). Skipped: testing and documentation
    advice, hardware-only advice, and requirements/policy items when enough
    actionable ones remain."""
    usable = [m for m in mitigations
              if not (set(m.get("phase") or []) <= {"Testing", "Documentation"})]
    software = [m for m in usable if "hardware" not in m.get("text", "").lower()]
    usable = software or usable
    actionable = [m for m in usable if set(m.get("phase") or []) & set(_FIX_PHASES)]
    if len(actionable) >= n:
        usable = actionable
    return [_first_sentences(m["text"]) for m in usable[:n] if m.get("text")]


# Weakness classes too broad for their mitigations to guide a fix: CWE-20's
# first is "consider using language-theoretic security techniques".
_GENERIC_CWES = {"CWE-20", "CWE-200", "CWE-693", "CWE-16"}


def mitre_cwe_guidance(finding: Finding) -> str:
    """MITRE's mitigations for the finding's weakness, labelled as general
    guidance, or "" when its weakness cannot be told.

    Not for a finding with a CVE: that is a flaw in someone else's product,
    fixed by the vendor's patch, not by redesigning the code (WinRAR's
    directory traversal, CVE-2025-6218, is not the customer's path handling).
    """
    kb = _cwe_kb()
    if not kb:
        return ""
    if any(str(c).upper().startswith("CVE-") for c in (finding.cve_list or [])):
        return ""

    def usable(c):
        e = kb.get(c)
        return bool(e) and c not in _GENERIC_CWES and e.get("abstraction") != "Pillar"

    cwe = next((str(c).upper() for c in (finding.cve_list or [])
                if str(c).upper().startswith("CWE-") and usable(str(c).upper())), None)
    if cwe is None:
        title = (finding.title or "").lower()
        cwe = next((c for pattern, c in _TITLE_TO_CWE if re.search(pattern, title) and usable(c)), None)
    if cwe is None:
        return ""
    entry = kb[cwe]
    steps = _pick_mitigations(entry.get("mitigations") or [])
    if not steps:
        return ""
    text = (f"General guidance from MITRE {cwe} ({entry.get('name', '')}), not from the report: "
            + " ".join(f"{i}. {s}" for i, s in enumerate(steps, 1)))
    sheet = entry.get("owasp_cheat_sheet")
    if sheet:
        text += f" See also: {sheet['title']} ({sheet['url']})."
    return text


# ── CISA Known Exploited Vulnerabilities ─────────────────────────────────────
# src/core/knowledge/cisa_kev.json, built by scripts/build_cisa_kev.py (CC0).
# A finding whose CVE is in the catalog is marked as exploited in the wild; its
# severity is never changed -- that is the scanner's.

_KEV = None


def _kev() -> dict:
    global _KEV
    if _KEV is None:
        import json
        import os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "knowledge", "cisa_kev.json")
        try:
            with open(path, encoding="utf-8") as fh:
                _KEV = json.load(fh).get("cves", {})
        except Exception:
            _KEV = {}
    return _KEV


def known_exploited(refs) -> list:
    """The CISA KEV entries for a finding's CVEs, in the order given:
    [{"cve", "date_added", "ransomware_use", "name", "required_action"}]."""
    kev, out, seen = _kev(), [], set()
    for ref in refs or []:
        cve = str(ref).strip().upper()
        if cve in kev and cve not in seen:
            seen.add(cve)
            e = kev[cve]
            out.append({"cve": cve, "date_added": e.get("date_added", ""),
                        "ransomware_use": e.get("ransomware_use", "Unknown"),
                        "name": e.get("name", ""), "required_action": e.get("required_action", "")})
    return out


def known_exploited_line(refs) -> str:
    """One line for a report: "CVE-2025-6218 is in CISA's Known Exploited
    Vulnerabilities catalog (listed 2025-12-09; known ransomware use: Unknown)"."""
    return "; ".join(f"{k['cve']} is in CISA's Known Exploited Vulnerabilities catalog "
                     f"(listed {k['date_added']}; known ransomware use: {k['ransomware_use']})"
                     for k in known_exploited(refs))


def get_actionable_remediation(finding: Finding) -> str:
    """
    Returns developer-actionable remediation guidance based on finding title/description.
    Uses a deterministic local template dictionary — 100% offline, no LLM required.

    When no template matches, this used to just return the scanner's own remediation
    text verbatim -- which made the exported report's "Developer Actionable Mitigation
    Steps" section silently disappear for that finding (report_exporter.py only shows
    it when the actionable text differs from the raw recommendation), since duplicating
    the same text under two headings has no display value. Any finding whose vulnerability
    type isn't one of the ~35 hardcoded keywords above -- a large share of real Nessus/
    Qualys CVE-based findings -- was getting no developer-specific guidance at all. Now
    builds a genuinely more actionable, structured fallback instead of parroting the
    scanner text back.
    """
    combined = f"{(finding.title or '').lower()} {(finding.description or '').lower()}"

    # ── PQC findings bypass the VAPT keyword templates entirely ───────────────
    # Without this guard, short keys like 'ssl' and 'tls' match PQC database/
    # TLS findings first, returning generic VAPT guidance ("Upgrade to TLS 1.2+")
    # instead of the correct PQC-specific actionable steps.
    _title_low = (finding.title or "").lower()
    _is_pqc = (
        (finding.category or "").upper() in (
            "PQC", "POST-QUANTUM CRYPTOGRAPHY",
            "ELLIPTIC CURVE CRYPTOGRAPHY (ECC)", "ASYMMETRIC ENCRYPTION (RSA)"
        )
        or (finding.control_id or "").upper().startswith("PQC")
        or bool(getattr(finding, "quantum_status", ""))
    )

    # Check each template key against combined text. Word-boundary matched, not plain
    # substring containment -- a bare `key in combined` check let short keys like "rce"
    # match inside unrelated words (enfoRCEd, souRCE, resouRCE, divoRCE...), handing out
    # wrong/irrelevant remediation guidance for findings that had nothing to do with
    # remote code execution.
    # The report's own CWE classification first. It is the tester's statement
    # of what the weakness IS, where the keyword scan below only spots words: a
    # finding titled "TLS cookie without secure flag set" matched the "tls"
    # template and was told to change TLS protocol versions, for a missing
    # cookie attribute (CWE-614).
    # The source gave no remediation.
    if not _is_pqc and not (finding.remediation or "").strip():
        # A CVE: the vendor's patch. The keyword templates below gave a
        # third-party product's CVE advice for the customer's own code --
        # "sanitize file path inputs" for WinRAR's CVE-2025-6218.
        _cve = next((c for c in (finding.cve_list or []) if str(c).upper().startswith("CVE-")), None)
        if _cve:
            _patch = (f"Apply the vendor-supplied patch addressing {_cve} for the affected component. "
                      "Verify the fix by re-running the scan against the affected target after remediation.")
            _kev_hit = known_exploited(finding.cve_list)
            if _kev_hit:
                k = _kev_hit[0]
                # CISA's own words, labelled; its due dates bind US federal
                # agencies and are not repeated here.
                return (f"Known to be exploited in the wild: {k['cve']} is in CISA's Known Exploited "
                        f"Vulnerabilities catalog (listed {k['date_added']}; known ransomware use: "
                        f"{k['ransomware_use']}). CISA's required action: {k['required_action']} " + _patch)
            return _patch
        # Otherwise MITRE's guidance for the weakness, where it is known,
        # ahead of the templates written here.
        _mitre = mitre_cwe_guidance(finding)
        if _mitre:
            return _mitre

    if not _is_pqc:
        for cwe in (str(c).upper() for c in (finding.cve_list or [])):
            if cwe in _CWE_REMEDIATION:
                return _CWE_REMEDIATION[cwe]

    if not _is_pqc:
        for key, guidance in _REMEDIATION_TEMPLATES.items():
            if re.search(rf'\b{re.escape(key)}\b', combined):
                return guidance

    # No keyword template matched.
    #
    # Only a CVE names a vulnerability a vendor can patch. cve_list also carries
    # CWE identifiers, and a CWE is a weakness CLASS -- CWE-601 is "open
    # redirect", not a defect in someone's product. Taking the first entry of
    # the list as the patch reference told developers to "apply the
    # vendor-supplied patch addressing CWE-601" for a flaw in their own code.
    cve_ref = next((c for c in (finding.cve_list or [])
                    if str(c).upper().startswith("CVE-")), None)
    base_remed = (finding.remediation or "").strip()

    # ── PQC findings: return a SHORT, genuinely distinct developer action list ──
    # The full multi-step remediation is already in finding.recommendation.
    # Repeating it here (with "Apply the fix: " prefix) makes both sections
    # look identical -- no value. Instead emit a concise per-algorithm action.
    # (_title_low and _is_pqc are set at the top of this function.)
    if _is_pqc:
        # Pick the shortest meaningful dev action by algorithm class
        if "rsa" in _title_low:
            return (
                "1. Audit all RSA key usages in this asset (TLS cert, SSH, JWT, S/MIME). "
                "2. Disable static-RSA cipher suites — keep only ECDHE-* (PFS) as interim. "
                "3. Re-issue the TLS certificate as ECDSA P-256 (short-term) or ML-DSA-65/FIPS-204 (post-quantum). "
                "4. Re-run the PQC scanner after each change to confirm the finding is resolved."
            )
        if "ecdsa" in _title_low:
            return (
                "1. Replace ECDSA TLS/SSH certificates with ML-DSA (FIPS 204) once your CA supports it. "
                "2. Interim: add X25519MLKEM768 to ssl_ecdh_curve to harden the key-exchange layer now. "
                "3. Migrate JWT / code-signing keys to ML-DSA-44 or ML-DSA-65. "
                "4. Re-run the PQC scanner after migration to confirm."
            )
        if "x25519" in _title_low or "curve25519" in _title_low:
            return (
                "1. Set ssl_ecdh_curve X25519MLKEM768:X25519; in NGINX — one config change enables hybrid PQC. "
                "2. For SSH: add sntrup761x25519-sha512@openssh.com to KexAlgorithms in sshd_config (OpenSSH 9.0+). "
                "3. Re-run the PQC scanner to confirm X25519MLKEM768 is detected as the active KEM."
            )
        if "secp384" in _title_low or "ecc" in _title_low or "elliptic" in _title_low:
            return (
                "1. Replace secp384r1 with X25519MLKEM768 hybrid in ssl_ecdh_curve — works with current OpenSSL 3.x. "
                "2. Plan certificate re-issuance to ML-DSA-65 (FIPS 204) once your CA supports PQC hybrids. "
                "3. Re-run the PQC scanner after each change to confirm no classical-only curves remain."
            )
        if "database" in _title_low or "mysql" in _title_low or "ssl cert" in _title_low or "ssl key" in _title_low or "sql" in _title_low:
            return (
                "1. Set tls_ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 in my.cnf. "
                "2. Set tls_version = TLSv1.3 and remove TLSv1.2 if still listed. "
                "3. Apply network compensating controls (private VPC, mTLS) while awaiting PQC-capable DB engine. "
                "4. Re-run the PQC scanner after config change to confirm TLS hardening is in effect."
            )
        if "tls" in _title_low or "protocol" in _title_low:
            return (
                "1. Add X25519MLKEM768 as the first entry in ssl_ecdh_curve for hybrid PQC key exchange. "
                "2. Ensure tls_version = TLSv1.3 only — disable TLSv1.2 if the client population allows. "
                "3. Re-run the PQC scanner to confirm ML-KEM hybrid is active in the TLS handshake."
            )
        # Generic PQC fallback
        return (
            "1. Identify the specific algorithm in use and its role (key exchange, signature, or encryption). "
            "2. Replace with the NIST-selected post-quantum equivalent: ML-KEM (FIPS 203) for key exchange, "
            "ML-DSA (FIPS 204) for signatures, SLH-DSA (FIPS 205) as alternative signature scheme. "
            "3. Re-run the PQC scanner after migration to confirm the finding is resolved."
        )

    # ── VAPT / CVE-based findings: structured actionable fallback ─────────────
    if cve_ref:
        fix_step = f"Apply the vendor-supplied patch addressing {cve_ref} for the affected component."
    elif base_remed:
        fix_step = f"Apply the fix: {base_remed}"
    else:
        fix_step = f"Apply the vendor-recommended fix for '{finding.title or 'this finding'}'."

    steps = [fix_step, "Verify the fix by re-running the scan against the affected target after remediation."]
    if not cve_ref and not base_remed:
        steps.append("If no vendor patch is available yet, apply compensating controls (network segmentation, a WAF rule, or disabling the affected service) until one is released.")

    return " ".join(steps)


# ══════════════════════════════════════════════════════════════════════════════
# UNIFIED ENRICHMENT PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def map_findings_list(findings: List[Finding]) -> List[Finding]:
    """
    Centralized mapper helper that enriches a list of Findings in-place:
    1. Assigns control_id (VAPT-1..VAPT-15)
    2. Assigns risk category (Access Control, Injection, etc.)
    3. Evaluates CIA impact & PII exposure
    4. Generates actionable developer remediation
    All operations are 100% offline and deterministic.
    """
    for f in findings:
        if not f.control_id:
            f.control_id = map_finding_to_control(f)
        if not f.category:
            f.category = map_finding_to_risk_category(f)
        if not f.cia_impact:
            cia_str, is_pii = evaluate_cia_and_pii_impact(f)
            f.cia_impact = cia_str
            f.is_pii_exposed = is_pii
        if not f.remediation_actionable:
            f.remediation_actionable = get_actionable_remediation(f)
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# PQC RISK SCORING  (Enhancement A -- CIA + HNDL Risk Scoring, 100% offline)
# ══════════════════════════════════════════════════════════════════════════════

def _cia_letter_score(cia_impact: str, letter: str) -> int:
    """Extracts one component's rating out of the 'C:HIGH | I:MEDIUM | A:NONE'
    -style cia_impact string produced by evaluate_cia_and_pii_impact() and maps
    it to a 1-5 score: HIGH -> 5, MEDIUM -> 3, NONE/blank/unrecognized -> 1.
    Substring-matched (not exact-equality) so the PII-exposure variant of the
    confidentiality value -- 'Confidential (High - PII Data Present)' -- still
    resolves to HIGH/5."""
    if not cia_impact:
        return 1
    for part in cia_impact.split("|"):
        part = part.strip()
        if part.upper().startswith(f"{letter}:"):
            val = part.split(":", 1)[1].strip().upper()
            if "HIGH" in val:
                return 5
            if "MEDIUM" in val:
                return 3
            return 1
    return 1


_BUSINESS_PRIORITY_CIA = {
    "CRITICAL": (5, 5, 4),
    "HIGH": (4, 4, 3),
    "MEDIUM": (3, 2, 2),
    "LOW": (2, 1, 1),
}


def _pqc_cia_scores(finding: Finding) -> "tuple":
    """
    C/I/A scores (1-5 each) for PQC risk scoring.

    The shared evaluate_cia_and_pii_impact() (via _cia_letter_score above) was
    built for VAPT findings and keys off text like "password"/"credential"/
    "injection" -- vocabulary that essentially never appears in a PQC finding's
    evidence ("Certificate : RSA2048"), so every PQC finding silently floored
    at C=I=A=1/NONE regardless of how critical the asset actually is.

    Instead, C/I/A for a PQC finding is driven by the asset's business
    criticality (finding.business_priority, Enhancement B) -- this also
    matches how the source RFP's own worked examples score CIA per business
    system, not per algorithm ("Internet Banking Portal": C=5/I=5/A=4;
    "Internal HR Portal": C=3/I=2/A=2 -- both reproduced exactly by this
    table for CRITICAL/MEDIUM respectively).

    Falls back to the shared VAPT-style keyword scorer (floored at a small
    baseline) only when the asset didn't match any business-priority keyword,
    so an unclassified asset isn't scored as zero-impact, and a genuine
    keyword hit (e.g. "credential") in that fallback still counts.
    """
    bp = (finding.business_priority or "").strip().upper()
    if bp in _BUSINESS_PRIORITY_CIA:
        return _BUSINESS_PRIORITY_CIA[bp]
    c = _cia_letter_score(finding.cia_impact, "C")
    i = _cia_letter_score(finding.cia_impact, "I")
    a = _cia_letter_score(finding.cia_impact, "A")
    return (max(c, 2), max(i, 2), max(a, 1))


def _hndl_score(exposure_context: str, quantum_status: str) -> int:
    """Harvest-Now-Decrypt-Later exposure factor (1-5), derived from
    exposure_context + quantum_status per the fixed lookup table below."""
    exp = (exposure_context or "").strip().upper()
    qs = (quantum_status or "").strip().upper()
    if exp == "EXTERNAL" and qs == "VULNERABLE":
        return 5
    if exp == "EXTERNAL" and qs == "WEAK":
        return 4
    if exp == "INTERNAL" and qs == "VULNERABLE":
        return 3
    if exp == "EXTERNAL" and qs == "SAFE":
        return 2
    if exp == "INTERNAL" and qs == "WEAK":
        return 2
    return 1


def _qv_score(quantum_status: str) -> int:
    """Quantum Vulnerability factor (1-5): VULNERABLE -> 5, WEAK -> 3,
    SAFE/blank -> 1."""
    qs = (quantum_status or "").strip().upper()
    if qs == "VULNERABLE":
        return 5
    if qs == "WEAK":
        return 3
    return 1


def compute_pqc_risk_score(finding: Finding) -> "tuple":
    """
    AICyberAuditBox PQC Risk Scoring Methodology
    ─────────────────────────────────────────────
    This tool's own defined, deterministic risk-scoring formula for PQC
    findings -- a weighted sum of 5 factors, each scored 1-5. It is NOT a
    reverse-engineered external standard (not CVSS, not FAIR, not any
    published PQC risk framework); it exists purely to give auditors a
    consistent 0-100 composite score to sort/prioritize PQC findings by.

        C    (Confidentiality impact) -- from finding.business_priority (see _pqc_cia_scores)
        I    (Integrity impact)       -- from finding.business_priority (see _pqc_cia_scores)
        A    (Availability impact)    -- from finding.business_priority (see _pqc_cia_scores)
        HNDL (Harvest-Now-Decrypt-Later exposure) -- from exposure_context + quantum_status
        QV   (Quantum Vulnerability)  -- from quantum_status

        risk_score = round((C + I + A + HNDL + QV) / 25 * 100)

    Banding: >= 80 -> CRITICAL, 60-79 -> HIGH, 40-59 -> MEDIUM, < 40 -> LOW.

    NOTE: requires finding.business_priority to already be set (classify_business_priority()
    must run before this in map_pqc_findings_list() -- it does, see call order below).

    Returns (risk_score: int, risk_band: str). 100% offline, deterministic --
    no LLM involvement.
    """
    c, i, a = _pqc_cia_scores(finding)
    hndl = _hndl_score(finding.exposure_context, finding.quantum_status)
    qv = _qv_score(finding.quantum_status)

    risk_score = round((c + i + a + hndl + qv) / 25 * 100)

    if risk_score >= 80:
        risk_band = "CRITICAL"
    elif risk_score >= 60:
        risk_band = "HIGH"
    elif risk_score >= 40:
        risk_band = "MEDIUM"
    else:
        risk_band = "LOW"

    return risk_score, risk_band


# ══════════════════════════════════════════════════════════════════════════════
# BUSINESS PRIORITY CLASSIFICATION  (Enhancement B -- 100% offline, keyword-based)
# ══════════════════════════════════════════════════════════════════════════════

# Ordered CRITICAL -> LOW so the most severe matching bucket wins when an
# asset description happens to contain keywords from more than one bucket
# (same "specific/severe checked first" convention as map_finding_to_control()
# and map_finding_to_pqc_control() above).
_BUSINESS_PRIORITY_BUCKETS = [
    ("CRITICAL", (
        "internet banking", "mobile banking", "core banking", "pki", "root ca",
        "vpn gateway", "payment switch", "payment", "swift", "atm",
    )),
    ("HIGH", (
        "api gateway", "api ", "load balancer", "firewall", "database",
        "oracle db", "customer data",
    )),
    ("MEDIUM", (
        "internal", "intranet", "hr portal", "employee", "erp",
    )),
    ("LOW", (
        "archive", "backup", "test environment", "sandbox", "staging",
    )),
]


def classify_business_priority(finding: Finding) -> str:
    """
    Deterministic business-criticality classification (Enhancement B) for a
    PQC finding's asset, based on keyword buckets matched against the asset's
    known context text. Searches (in order of richness):
      1. asset_category  -- already classified by _classify_asset_category()
         e.g. 'Load Balancer' -> HIGH, 'PKI / HSM' -> CRITICAL
      2. asset_name / target -- filename fallback from _find_asset_context()
      3. title -- algorithm name (last resort)
    Same style as map_finding_to_risk_category(): fixed ordered keyword lookup,
    100% offline. Returns "" when nothing matches -- never forces a guess.
    """
    # Build combined text: asset_category first (most reliable signal),
    # then asset_name / target, then title as last resort.
    combined = " ".join(filter(None, [
        getattr(finding, "asset_category", "") or "",
        finding.asset_name or "",
        finding.target or "",
        finding.title or "",
    ])).lower()
    for band, keywords in _BUSINESS_PRIORITY_BUCKETS:
        if any(kw in combined for kw in keywords):
            return band
    return ""


def map_pqc_findings_list(findings: List[Finding]) -> List[Finding]:
    """
    PQC-specific variant of map_findings_list(): identical enrichment (risk
    category, CIA impact/PII, actionable remediation), but assigns control_id
    via map_finding_to_pqc_control() (PQC-1..PQC-12) instead of
    map_finding_to_control() (VAPT-1..15) -- called from pqc_parser.py so PQC
    findings never get mis-mapped to a VAPT control ID.

    Idempotent like map_findings_list(): every assignment is guarded by
    `if not f.<field>`, so a later generic map_findings_list() re-pass (e.g.
    parsers/__init__.py's parse_tool_file()) is a no-op for anything already
    set here -- the PQC-specific control_id survives.
    """
    for f in findings:
        if not f.control_id:
            f.control_id = map_finding_to_pqc_control(f)
        if not f.category:
            f.category = map_finding_to_risk_category(f)
        if not f.cia_impact:
            cia_str, is_pii = evaluate_cia_and_pii_impact(f)
            f.cia_impact = cia_str
            f.is_pii_exposed = is_pii
        if not f.remediation_actionable:
            f.remediation_actionable = get_actionable_remediation(f)
        # Enhancement B: business priority classification -- must run BEFORE
        # Enhancement A below, since compute_pqc_risk_score()'s C/I/A factors
        # are now derived from finding.business_priority (see _pqc_cia_scores).
        if not f.business_priority:
            f.business_priority = classify_business_priority(f)
        # Enhancement A: CIA + HNDL PQC risk score. Only computed for actual
        # problems (VULNERABLE/WEAK) -- a SAFE finding (e.g. AES-256) sitting
        # on a business-critical system would otherwise inherit that system's
        # high C/I/A weighting and surface a misleading "68/HIGH" risk score
        # for an algorithm that needs no remediation at all. Same reasoning
        # that already routes SAFE findings to info_findings (not actionable)
        # in pqc_parser.py. Guarded on risk_score is None for idempotency.
        if f.quantum_status in ("VULNERABLE", "WEAK") and f.risk_score is None:
            f.risk_score, f.risk_band = compute_pqc_risk_score(f)
    return findings
