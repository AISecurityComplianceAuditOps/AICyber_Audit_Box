# -*- coding: utf-8 -*-
"""
TLS scanner parser: testssl.sh (--csvfile, --jsonfile, --jsonfile-pretty and
the console log) and sslscan (console).

Neither was read before: a server offering TLS 1.0, 3DES and RC4 with an
expired certificate produced zero findings from either tool.

testssl.sh rates every check itself (OK/INFO/LOW/MEDIUM/HIGH/CRITICAL); that
rating is kept, and only LOW and above become findings -- its hundreds of OK
and INFO rows are the checks that passed. sslscan rates nothing, so its
weaknesses are rated the way this product's nmap parser rates the same ones
(deprecated protocol MEDIUM, weak cipher MEDIUM), so one weakness does not get
two severities depending on which tool found it.
"""
import csv
import io
import json
import re
from typing import Any, List, Tuple

from .base_parser import BaseParser, is_image_file
from .finding_schema import Finding

# testssl.sh check ids -> what they are, for a readable title.
_TESTSSL_NAMES = {
    "SSLv2": "SSLv2 protocol", "SSLv3": "SSLv3 protocol",
    "TLS1": "TLS 1.0 protocol (TLS1)", "TLS1_1": "TLS 1.1 protocol (TLS1_1)",
    "heartbleed": "Heartbleed", "CCS": "CCS injection", "ticketbleed": "Ticketbleed",
    "ROBOT": "ROBOT", "secure_renego": "Secure renegotiation",
    "secure_client_renego": "Client-initiated renegotiation", "CRIME_TLS": "CRIME",
    "BREACH": "BREACH", "POODLE_SSL": "POODLE (SSL)", "fallback_SCSV": "TLS_FALLBACK_SCSV",
    "SWEET32": "SWEET32", "FREAK": "FREAK", "DROWN": "DROWN", "LOGJAM": "LOGJAM",
    "BEAST": "BEAST", "LUCKY13": "LUCKY13", "RC4": "RC4 ciphers", "winshock": "Winshock",
    "cert_expirationStatus": "Certificate expiration", "cert_chain_of_trust": "Certificate chain of trust",
    "cert_trust": "Certificate trust", "cert_signatureAlgorithm": "Certificate signature algorithm",
    "cert_keySize": "Certificate key size", "HSTS": "HSTS", "cipherlist_NULL": "NULL ciphers",
    "cipherlist_aNULL": "Anonymous (aNULL) ciphers", "cipherlist_EXPORT": "EXPORT ciphers",
    "cipherlist_LOW": "Low-strength ciphers", "cipherlist_3DES_IDEA": "3DES/IDEA ciphers",
    "cipherlist_OBSOLETED": "Obsolete CBC ciphers",
}
_RATED = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

_WEAK_CIPHER_RE = re.compile(r'(?<![A-Z0-9])(?:RC4|DES|3DES|DES-CBC3|NULL|EXP|EXPORT|ADH|AECDH|anon|MD5|IDEA)(?![A-Z0-9])',
                             re.IGNORECASE)


def _testssl_target(fqdn_ip: str, port: str) -> str:
    host, _, ip = str(fqdn_ip or "").partition("/")
    label = f"{host} ({ip})" if host and ip and host != ip else (host or ip or "Target Host")
    return f"{label}:{port}" if port else label


def _testssl_finding(rec: dict) -> Finding:
    tid = str(rec.get("id", "")).strip()
    sev = str(rec.get("severity", "")).strip().upper()
    text = str(rec.get("finding", "")).strip()
    cves = [c.upper() for c in re.findall(r'CVE-\d{4}-\d{4,7}', str(rec.get("cve", "")), re.IGNORECASE)]
    cwes = [c.upper() for c in re.findall(r'CWE-\d+', str(rec.get("cwe", "")), re.IGNORECASE)]
    name = _TESTSSL_NAMES.get(tid, tid)
    target = _testssl_target(rec.get("fqdn/ip") or rec.get("ip") or "", str(rec.get("port", "")))
    return Finding(
        title=f"{name}: {text}"[:160],
        severity=sev,
        cve_list=cves + cwes,
        target=target,
        description=f"testssl.sh check '{tid}' on {target} reported: {text}.",
        remediation=_tls_fix(tid + " " + text),
        evidence=f"{tid}  {sev}  {text}",
        plugin_id=tid,
        source_tool="testssl.sh",
    )


def _tls_fix(what: str) -> str:
    w = what.lower()
    if "sslv2" in w or "sslv3" in w or "tls1" in w or "tls 1.0" in w or "tls 1.1" in w or "tlsv1.0" in w or "tlsv1.1" in w:
        return "Disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1; offer TLS 1.2 and TLS 1.3 only."
    if "expir" in w or "chain" in w or "trust" in w:
        return "Replace the certificate with a valid one issued by a trusted CA, with the full chain installed."
    if "heartbleed" in w:
        return "Upgrade OpenSSL to a fixed release, then revoke and reissue the certificate and rotate keys."
    if "renego" in w:
        return "Disable client-initiated renegotiation and require secure renegotiation (RFC 5746)."
    if "hsts" in w:
        return "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on HTTPS responses."
    if "crime" in w or "compression" in w:
        return "Disable TLS-level compression."
    return ("Remove weak ciphers (RC4, 3DES, DES, NULL, EXPORT, anonymous, CBC-only suites where "
            "possible) and prefer AEAD suites with forward secrecy (ECDHE with AES-GCM or ChaCha20).")


def _tls_dev_steps(what: str) -> str:
    w = what.lower()
    if re.search(r'sslv2|sslv3|tls ?1\.0|tls ?1\.1|tlsv1\.[01]|\btls1(_1)?\b|beast|poodle', w):
        return ("1. In the web server / load balancer TLS settings, disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1 "
                "(nginx: ssl_protocols TLSv1.2 TLSv1.3; Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3). "
                "2. Reload the service. 3. Re-run the TLS scan and confirm only TLS 1.2/1.3 are offered.")
    if "expir" in w or "chain" in w or "trust" in w:
        return ("1. Obtain a new certificate from a trusted CA for this host name. 2. Install it with the full "
                "intermediate chain. 3. Re-run the TLS scan and confirm the certificate is valid and trusted.")
    if "heartbleed" in w:
        return ("1. Upgrade OpenSSL to a fixed release and restart every service linked against it. "
                "2. Revoke and reissue the certificate with a new private key. 3. Rotate session secrets and passwords.")
    if "renegotiation" in w:
        return "1. Disable client-initiated renegotiation in the TLS configuration. 2. Re-run the TLS scan."
    if "compression" in w or "crime" in w:
        return "1. Disable TLS compression in the TLS library / server configuration. 2. Re-run the TLS scan."
    if "key" in w and "rsa" in w:
        return "1. Generate an RSA 2048-bit (or ECDSA P-256) key and reissue the certificate. 2. Install it and re-run the TLS scan."
    if "signature" in w:
        return "1. Reissue the certificate signed with SHA-256. 2. Install it and re-run the TLS scan."
    if "hsts" in w:
        return ("1. Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to every HTTPS response. "
                "2. Re-run the scan.")
    return ("1. Remove RC4, 3DES/DES, NULL, EXPORT and anonymous cipher suites from the server's cipher list. "
            "2. Prefer ECDHE suites with AES-GCM or ChaCha20-Poly1305. 3. Re-run the TLS scan and confirm "
            "no weak suite is accepted.")


class TlsScanParser(BaseParser):
    def can_parse(self, filename: str, content: str) -> bool:
        if not content or is_image_file(filename):
            return False
        return bool(self._kind(content))

    @staticmethod
    def _kind(content: str) -> str:
        head = content.lstrip()[:600]
        if re.match(r'"id","fqdn/ip","port","severity","finding"', head):
            return "testssl_csv"
        if head[:1] in "[{" and '"finding"' in content and '"severity"' in content and (
                '"fqdn/ip"' in content or '"scanResult"' in content or re.search(r'"id"\s*:\s*"(?:SSLv2|TLS1|service|heartbleed)"', content)):
            return "testssl_json"
        if re.search(r'testssl\.sh\s+[\d.]+|Start \d{4}-\d{2}-\d{2} [\d:]+\s+-->>', content):
            return "testssl_console"
        if re.search(r'Testing SSL server \S+ on port \d+', content):
            return "sslscan"
        return ""

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], Any]:
        findings = self._findings(content)
        # Every result here is a TLS configuration weakness. Set before the
        # shared mapper runs, which fills only empty fields: its CWE lookup put
        # BEAST under Injection (testssl tags it CWE-20), and its CWE-327
        # template told a TLS cipher finding how to hash passwords.
        for f in findings:
            f.category = "Cryptographic Failures"
            # The title, not the evidence: a cipher's evidence names the
            # protocol it was offered on ("RC4-SHA (TLSv1.0, 128 bits)").
            f.remediation_actionable = _tls_dev_steps(f.title)
        return findings, []

    def _findings(self, content: str) -> List[Finding]:
        kind = self._kind(content)
        if kind == "testssl_csv":
            recs = list(csv.DictReader(io.StringIO(content.strip())))
            findings = [_testssl_finding(r) for r in recs if str(r.get("severity", "")).upper() in _RATED]
        elif kind == "testssl_json":
            findings = [_testssl_finding(r) for r in self._testssl_json(content)
                        if str(r.get("severity", "")).upper() in _RATED]
        elif kind == "testssl_console":
            findings = self._testssl_console(content)
        elif kind == "sslscan":
            findings = self._sslscan(content)
        else:
            findings = []
        return findings

    @staticmethod
    def _testssl_json(content: str) -> List[dict]:
        try:
            data = json.loads(content)
        except ValueError:
            return []
        if isinstance(data, list):                       # --jsonfile: flat list
            return [r for r in data if isinstance(r, dict)]
        out = []                                         # --jsonfile-pretty
        for res in data.get("scanResult") or []:
            where = f"{res.get('targetHost', '')}/{res.get('ip', '')}"
            for section, rows in res.items():
                if isinstance(rows, list):
                    for r in rows:
                        if isinstance(r, dict) and "id" in r:
                            out.append({**r, "fqdn/ip": where, "port": res.get("port", "")})
        return out

    @staticmethod
    def _testssl_console(content: str) -> List[Finding]:
        m = re.search(r'Start \d{4}-\d{2}-\d{2} [\d:]+\s+-->>\s*(\S+):(\d+)\s*\(([^)]*)\)', content)
        target = f"{m.group(3)} ({m.group(1)}):{m.group(2)}" if m else "Target Host"
        out = []
        for line in content.splitlines():
            s = re.sub(r'\x1b\[[0-9;]*m', '', line).rstrip()
            low = s.lower()
            pm = re.match(r'^\s*(SSLv2|SSLv3|TLS 1(?:\.1)?)\s+offered', s)
            if pm and ("not ok" in low or "deprecated" in low):
                sev = "HIGH" if pm.group(1).startswith("SSL") else "LOW"
                out.append(Finding(title=f"{pm.group(1)} offered", severity=sev, target=target,
                                   description=f"testssl.sh: {s.strip()}", remediation=_tls_fix(pm.group(1)),
                                   evidence=s.strip(), source_tool="testssl.sh"))
                continue
            vm = re.match(r'^\s*([A-Z][\w /()-]*?)\s+\(([^)]*CVE[^)]*)\)\s+(.*VULNERABLE.*)$', s)
            if vm and "not vulnerable" not in low:
                cves = [c.upper() for c in re.findall(r'CVE-\d{4}-\d{4,7}', vm.group(2), re.IGNORECASE)]
                sev = "HIGH" if re.search(r'heartbleed|ccs|robot|drown|ticketbleed', vm.group(1), re.IGNORECASE) else "LOW"
                out.append(Finding(title=f"{vm.group(1).strip()}: {vm.group(3).strip()}"[:160], severity=sev,
                                   cve_list=cves, target=target, description=f"testssl.sh: {s.strip()}",
                                   remediation=_tls_fix(vm.group(1)), evidence=s.strip(), source_tool="testssl.sh"))
                continue
            if re.match(r'^\s*Certificate Validity \(UTC\)\s+expired', s):
                out.append(Finding(title="Certificate expired", severity="CRITICAL", target=target,
                                   description=f"testssl.sh: {s.strip()}", remediation=_tls_fix("expired"),
                                   evidence=s.strip(), source_tool="testssl.sh"))
        return out

    @staticmethod
    def _sslscan(content: str) -> List[Finding]:
        m = re.search(r'Testing SSL server (\S+) on port (\d+)', content)
        ip = re.search(r'Connected to (\S+)', content)
        host = m.group(1) if m else ""
        label = f"{host} ({ip.group(1)})" if host and ip and ip.group(1) != host else (host or (ip.group(1) if ip else "Target Host"))
        target = f"{label}:{m.group(2)}" if m else label
        out = []

        old = [p for p in re.findall(r'^(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)\s+enabled', content, re.MULTILINE)]
        if old:
            sev = "HIGH" if any(p.startswith("SSL") for p in old) else "MEDIUM"
            out.append(Finding(
                title=f"Weak SSL/TLS Protocol Supported: {', '.join(old)}", severity=sev, target=target,
                description=f"sslscan found {', '.join(old)} enabled on {target}.",
                remediation=_tls_fix("tls1"),
                evidence="\n".join(f"{p} enabled" for p in old), source_tool="sslscan"))

        weak = []
        for cm in re.finditer(r'^(?:Preferred|Accepted)\s+(\S+)\s+(\d+) bits\s+(\S+)', content, re.MULTILINE):
            proto, bits, name = cm.group(1), int(cm.group(2)), cm.group(3)
            if bits < 128 or _WEAK_CIPHER_RE.search(name):
                weak.append(f"{name} ({proto}, {bits} bits)")
        if weak:
            out.append(Finding(
                title=f"Weak Cipher Suites Supported: {', '.join(w.split(' ')[0] for w in weak[:5])}",
                severity="MEDIUM", target=target,
                description=f"sslscan found {len(weak)} weak cipher suite(s) accepted on {target}: {', '.join(weak)}.",
                remediation=_tls_fix("cipher"),
                evidence="\n".join(weak), source_tool="sslscan"))

        hb = re.findall(r'^(\S+) vulnerable to heartbleed', content, re.MULTILINE)
        if hb:
            out.append(Finding(
                title="Heartbleed (CVE-2014-0160)", severity="CRITICAL", cve_list=["CVE-2014-0160"], target=target,
                description=f"sslscan reports {', '.join(hb)} vulnerable to Heartbleed on {target}.",
                remediation=_tls_fix("heartbleed"),
                evidence="\n".join(f"{p} vulnerable to heartbleed" for p in hb), source_tool="sslscan"))
        if re.search(r'^Insecure session renegotiation supported', content, re.MULTILINE):
            out.append(Finding(title="Insecure TLS renegotiation supported", severity="MEDIUM", target=target,
                               description=f"sslscan reports insecure session renegotiation on {target}.",
                               remediation=_tls_fix("renego"), evidence="Insecure session renegotiation supported",
                               source_tool="sslscan"))
        if re.search(r'^Compression enabled', content, re.MULTILINE):
            out.append(Finding(title="TLS compression enabled (CRIME)", severity="MEDIUM", target=target,
                               description=f"sslscan reports TLS compression enabled on {target} (CRIME).",
                               remediation=_tls_fix("compression"), evidence="Compression enabled",
                               source_tool="sslscan"))
        key = re.search(r'^RSA Key Strength:\s*(\d+)', content, re.MULTILINE)
        if key and int(key.group(1)) < 2048:
            out.append(Finding(title=f"Weak certificate key: RSA {key.group(1)} bits", severity="MEDIUM", target=target,
                               description=f"The certificate on {target} uses a {key.group(1)}-bit RSA key.",
                               remediation="Reissue the certificate with an RSA key of at least 2048 bits (or ECDSA P-256).",
                               evidence=key.group(0), source_tool="sslscan"))
        sig = re.search(r'^Signature Algorithm:\s*(\S*(?:md5|sha1)\S*)', content, re.MULTILINE | re.IGNORECASE)
        if sig:
            out.append(Finding(title=f"Weak certificate signature: {sig.group(1)}", severity="MEDIUM", target=target,
                               description=f"The certificate on {target} is signed with {sig.group(1)}.",
                               remediation="Reissue the certificate signed with SHA-256 or stronger.",
                               evidence=sig.group(0), source_tool="sslscan"))
        return out
