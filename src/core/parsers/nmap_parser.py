# -*- coding: utf-8 -*-
import re
from datetime import datetime
import xml.etree.ElementTree as ET
from typing import List, Tuple, Dict, Any
from .base_parser import BaseParser, is_image_file
from .finding_schema import Finding
from .control_mapper import map_findings_list

class AssetInventory:
    def __init__(self, target_ip: str = "", open_ports: List[Dict[str, str]] = None):
        self.target_ip = target_ip
        self.open_ports = open_ports or []

# NSE output frequently flags real misconfigurations (weak TLS, unauthenticated services,
# directory listings, default creds) without naming a "*-vuln*" script or citing a CVE.
# These keyword heuristics catch that class of finding.
_RISK_KEYWORDS = [
    # Loosened from full exact phrases (e.g. "unauthenticated access permitted") --
    # real NSE script output and OCR'd screenshots vary in wording ("Unauthenticated
    # Access", "unauthenticated login", "unauth. access") and never matched the
    # original narrow phrasing, silently dropping real findings. Matching is already
    # scoped to a single port's own block of text (see the per-port loop below), so
    # a bare keyword hit here is still contextually tied to that specific port/
    # service, not a free-floating substring match across the whole document.
    (re.compile(r'\bunauthenticated\b', re.IGNORECASE), "HIGH", "Unauthenticated Service Access"),
    (re.compile(r'\banonymous\b.{0,20}\b(?:login|ftp|access|bind)\b', re.IGNORECASE), "HIGH", "Anonymous Authentication Allowed"),
    (re.compile(r'weak protocol detected|non-compliant', re.IGNORECASE), "MEDIUM", "Weak/Deprecated Protocol Supported"),
    (re.compile(r'\btlsv?1\.0\b|\bsslv[23]\b', re.IGNORECASE), "MEDIUM", "Weak SSL/TLS Protocol Supported"),
    (re.compile(r'\b(?:unencrypted|cleartext|clear-text|plaintext|plain-text)\b', re.IGNORECASE), "MEDIUM", "Unencrypted Service Connection Allowed"),
    (re.compile(r'index of /', re.IGNORECASE), "LOW", "Directory Listing Enabled"),
    (re.compile(r'default (?:credentials|password)', re.IGNORECASE), "HIGH", "Default Credentials in Use"),
    # Weak ciphers. ssl-enum-ciphers lists them by name ("TLS_RSA_WITH_3DES_EDE_
    # CBC_SHA - weak") and grades the port ("least strength: weak" / C-F), and
    # none of that was recognised: a scan of 399 hosts all offering 3DES under
    # TLS 1.0 raised only the protocol. The token is bounded by non-alphanumerics
    # rather than \b, because in a cipher name it sits between underscores,
    # which are word characters. "NULL" is deliberately absent: the same script
    # prints "compressors: NULL" on every healthy port.
    # "weak ... cipher(s)" catches SSH too ("OpenSSH 7.2p2 (Weak CBC ciphers)"),
    # so the label names no protocol.
    (re.compile(r'(?<![a-z0-9])(?:3des|des-cbc3|rc4)(?![a-z0-9])|least strength:\s*(?:weak|[def])\b'
                r'|\bweak\s+(?:[\w-]+\s+){0,2}ciphers?\b',
                re.IGNORECASE), "MEDIUM", "Weak Cipher Suites Supported"),
]

# Two rules can name the SAME issue on one line: "ssl-date: TLSv1.0 (WEAK
# PROTOCOL DETECTED - PCI-DSS NON-COMPLIANT)" matches both the generic
# weak-protocol rule and the TLS-version rule. When the specific one fires, the
# generic one is dropped, so one weakness is one finding.
_SUPERSEDED_BY = {"Weak/Deprecated Protocol Supported": "Weak SSL/TLS Protocol Supported"}

# Services that are a finding merely by being open. Telnet and the BSD
# r-services carry credentials and sessions in clear text; every scanner in
# common use reports them, and a 399-host scan with Telnet open on every host
# produced no finding for it at all, because nothing looked at the service name.
_RISKY_SERVICES = {
    "telnet": ("HIGH", "Cleartext Remote Login Service (Telnet)"),
    "login": ("HIGH", "Cleartext Remote Login Service (rlogin)"),
    "shell": ("HIGH", "Cleartext Remote Shell Service (rsh)"),
    "exec": ("HIGH", "Cleartext Remote Execution Service (rexec)"),
}

# Named vulnerabilities whose severity is not in doubt, for CVE mentions that
# carry no rating of their own. Words, not CVSS numbers: nmap publishes no
# score, and this does not invent one.
_CRITICAL_NAMES = ("backdoor", "bluekeep", "eternalblue", "shellshock", "log4shell",
                   "remote code execution", "wormable")
_HIGH_NAMES = ("path traversal", "directory traversal", "heartbleed", "sql injection",
               "authentication bypass")

def _cleartext_service_steps(findings) -> None:
    """Developer steps for an open Telnet / r-service, set before the shared
    mapper runs: its "cleartext" template answers with FTPS/SFTP/HTTPS, none of
    which replaces a remote shell."""
    from .kali_parser import _cleartext_login_steps
    for f in findings:
        if "Cleartext Remote" in f.title and not f.remediation_actionable:
            m = re.search(r'\((\d+)/tcp\)', f.title)
            f.remediation_actionable = _cleartext_login_steps(m.group(1) if m else "the port", f.target)


def _clean_nmap_title(raw: str) -> str:
    """Tidy a title lifted out of raw nmap output.

    The NSE/CVE regex captures from the CVE token to end of line, so a real
    ssl-enum-ciphers line --

        TLS_RSA_WITH_AES_128_CBC_SHA (dh 2048) - Vulnerable to LUCKY13 (CVE-2013-0169)

    -- yielded the title "Vuln Finding: CVE-2013-0169)", complete with the orphan
    bracket the capture started inside. That string goes straight into the
    customer's report.
    """
    t = re.sub(r'\s+', ' ', str(raw or '')).strip()
    t = t.lstrip('|_ ').strip()
    # Drop a closing bracket whose opener the capture never included.
    if t.count(")") > t.count("("):
        t = t.replace(")", "", t.count(")") - t.count("("))
    if t.count("]") > t.count("["):
        t = t.replace("]", "", t.count("]") - t.count("["))
    t = re.sub(r'[\s\-–,;:]+$', '', t)
    return t.strip()


def _severity_for_cve_line(line: str, cves: List[str]) -> str:
    """Severity for a CVE mention that carries no stated rating.

    Every CVE hit used to be flat "HIGH". Nmap does not publish a severity, so
    that was an assumption, and it collided head-on with the other scanner: the
    same CVE-2013-0169 was HIGH here and Low (CVSS 2.3) in the Nessus report from
    the same engagement. Two severities for one vulnerability in one report pack
    is the first thing an auditor challenges.

    Without an offline CVE database an exact CVSS cannot be derived, so this reads
    what the line itself says and otherwise settles on MEDIUM -- an honest
    "unrated finding, needs triage" rather than an invented HIGH.
    """
    low = (line or "").lower()
    # Explicit severity statements are checked BEFORE the keyword heuristics: a line
    # that says "Low severity" is telling us the answer directly, and letting the
    # CRITICAL keyword list pre-empt it means one incidental word overrides the
    # scanner's own rating.
    if any(k in low for k in ("low severity", "severity: low", "informational")):
        return "LOW"
    if any(k in low for k in ("high severity", "severity: high")):
        return "HIGH"
    # "unauthenticated" alone is not a finding -- Nmap script output says it in
    # both directions ("unauthenticated access is DISABLED" is a PASS). Require it
    # to be paired with a word that indicates the access is actually available,
    # and treat an explicit negation as disqualifying.
    _unauth_bad = (
        re.search(r'unauthenticated[^.]{0,40}\b(allowed|permitted|enabled|possible|successful|access granted)\b', low)
        and not re.search(r'\b(disabled|denied|blocked|not allowed|prevented|rejected)\b', low)
    )
    if any(k in low for k in ("critical", "remote code execution")) or re.search(r'(?<![a-z])rce(?![a-z])', low) or _unauth_bad:
        return "CRITICAL"
    # A confirmed backdoor (vsftpd 2.3.4, CVE-2011-2523) and BlueKeep came out
    # MEDIUM: their lines named the vulnerability but used none of the words
    # above.
    if any(k in low for k in _CRITICAL_NAMES):
        return "CRITICAL"
    if any(k in low for k in _HIGH_NAMES):
        return "HIGH"
    # Known weak-crypto / padding-oracle classes are consistently rated low-to-
    # medium by scanners; naming them HIGH is what caused the clash above.
    # Word-anchored: "cbc" as a bare substring matches inside hex certificate
    # fingerprints ("9acbcb2e..."), which appear throughout ssl-cert script output
    # and would silently promote unrelated lines from LOW to MEDIUM.
    if any(re.search(r'(?<![a-z0-9])' + k + r'(?![a-z0-9])', low)
           for k in ("lucky13", "sweet32", "beast", "poodle", "cbc", "cipher")):
        return "MEDIUM"
    return "MEDIUM" if cves else "LOW"



# One line per port: "443/tcp open ssl/http Apache httpd 2.4.6". The state must
# be one nmap actually prints, so a "Port: 80/tcp" mention in prose is not read
# as a port line.
_PORT_LINE_RE = re.compile(
    r'(?mi)^[ \t|_]*(\d+/(?:tcp|udp|sctp))[ \t]+'
    r'(open\|filtered|closed\|filtered|open|closed|filtered|unfiltered)[ \t]+'
    r'(\S+)[ \t]*([^\n]*)$')

# "Nmap scan report for HOST" -- also "# Nmap 7.92 scan report for HOST", the
# form in several evidence files, which the old header pattern did not accept,
# so every finding in them was attributed to "Target Host".
_HOST_HEADER_RE = re.compile(r'(?mi)^[ \t#]*Nmap(?:[ \t]+[\d.]+)?[ \t]+scan report for[ \t]+([^\n]+?)[ \t]*$')


def _split_hosts(content):
    """[(target_label, that host's section)] in document order."""
    heads = list(_HOST_HEADER_RE.finditer(content))
    out = []
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(content)
        out.append((m.group(1).strip(), content[m.end():end]))
    return out


def _scan_date(content):
    """When the scan ran, if the output says; None otherwise.

    Certificate expiry is judged against this, not against today: a report is
    evidence of the state at scan time, and a certificate that expired after the
    scan was valid when the auditor looked.
    """
    m = re.search(r'scan initiated\s+\w{3}\s+(\w{3})\s+(\d{1,2})\s+[\d:]+\s+(\d{4})', content)
    if not m:
        m = re.search(r'Nmap done at\s+\w{3}\s+(\w{3})\s+(\d{1,2})\s+[\d:]+\s+(\d{4})', content)
    if not m:
        return None
    try:
        return datetime.strptime(f"{m.group(1)} {m.group(2)} {m.group(3)}", "%b %d %Y").date()
    except ValueError:
        return None


class NmapParser(BaseParser):
    def can_parse(self, filename: str, content: str) -> bool:
        """Content-signature based detection — 0% filename keyword dependency.
        Rejects image files immediately, then inspects structural content
        that is exclusive to Nmap scan outputs (XML or plain text).
        """
        if not content:
            return False
        # Guard: reject image files regardless of their filename.
        if is_image_file(filename):
            return False
        # Content-signature: XML format (<nmaprun>) or plain-text Nmap console output.
        # (Previously also matched on a bare .nmap/.gnmap extension with no content check
        # at all, contradicting this method's own "0% filename keyword dependency" claim
        # above -- any file merely named *.nmap, regardless of actual content, would have
        # been claimed here unconditionally.)
        # Scans the FULL content, not a fixed-size prefix -- see burp_parser.py/
        # nessus_parser.py for why a fixed window isn't safe against real-world
        # exports with large preambles (e.g. Nmap output embedded further down
        # in a combined/larger report file).
        sample = content.lower()
        if "<nmaprun" in sample or "starting nmap" in sample or "nmap scan report for" in sample:
            return True
        # Grepable output (-oG / .gnmap): "Host: <ip> ... Status: ..." line structure --
        # same signature parse() itself uses to decide whether to call _parse_grepable().
        # Doesn't share any of the phrases above, so needs its own check now that the
        # extension-only shortcut is gone.
        if re.search(r'^Host:\s+\S+.*Status:', content, re.MULTILINE):
            return True
        # Plain-text output distinctive pattern: 'PORT   STATE   SERVICE'
        if re.search(r'\bport\s+state\s+service\b', sample):
            return True
        return False

    def _parse_xml(self, content: str) -> Tuple[List[Finding], AssetInventory]:
        """Parses nmap's native XML output (-oX), e.g. <nmaprun><host><ports><port>
        <script id=... output=.../></port></ports></host></nmaprun>. Distinct from the
        plain-text (-oN) console output handled by parse() below."""
        findings: List[Finding] = []
        open_ports: List[Dict[str, str]] = []
        target_label = "Target Host"
        seen_evidence = set()

        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return [], AssetInventory()

        def _add_finding(title: str, severity: str, cves: List[str], evidence: str, port_label: str = ""):
            ev_key = evidence.strip()
            # Keyed by host too: keyed on evidence alone, identical script output
            # on a second host was dropped as a duplicate of the first.
            key = (target_label, port_label, title, tuple(sorted(cves or [])), ev_key)
            if key in seen_evidence:
                return
            seen_evidence.add(key)
            findings.append(Finding(
                title=f"Nmap: {title}" + (f" ({port_label})" if port_label else ""),
                severity=severity,
                cve_list=cves,
                target=target_label,
                # Evidence folded into the description, not left boilerplate-only --
                # matches the fix already applied in parse()'s plain-text path below
                # (see its own _add_finding for the full story): map_finding_to_owasp()
                # classifies on title+description, and a description with no
                # vulnerability signal in it sends every finding to the A05 default
                # regardless of what the NSE script actually reported.
                description=f"Nmap NSE script detection on target {target_label}"
                            f"{(' port ' + port_label) if port_label else ''}: {ev_key}",
                remediation="Investigate service misconfiguration and apply vendor patches/hardening.",
                evidence=ev_key,
                source_tool="Nmap"
            ))

        def _check_script(script_el, port_label=""):
            script_id = script_el.get('id', '')
            output = script_el.get('output', '') or (script_el.text or '')
            if not output:
                return
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', output, re.IGNORECASE)
            combined = f"{script_id}: {output}".strip()
            if '-vuln' in script_id.lower() or cves:
                _add_finding(f"Vuln Script Finding: {combined[:60]}", "HIGH" if cves else "MEDIUM", cves, combined, port_label)
            for pattern, severity, label in _RISK_KEYWORDS:
                if pattern.search(output):
                    _add_finding(label, severity, [], output.strip(), port_label)

        for host in root.findall('host'):
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host.find('address')
            ip = addr_el.get('addr', '') if addr_el is not None else ""
            hostname_el = host.find('hostnames/hostname')
            hostname = hostname_el.get('name', '') if hostname_el is not None else ""
            target_label = f"{hostname} ({ip})" if hostname and ip else (ip or hostname or "Target Host")

            for port_el in host.findall('ports/port'):
                portid = port_el.get('portid', '')
                protocol = port_el.get('protocol', 'tcp')
                port_label = f"{portid}/{protocol}" if portid else ""

                state_el = port_el.find('state')
                state = state_el.get('state', '') if state_el is not None else ''

                service_el = port_el.find('service')
                svc_parts = []
                if service_el is not None:
                    for attr in ('name', 'product', 'version'):
                        val = service_el.get(attr, '')
                        if val:
                            svc_parts.append(val)
                svc_str = " ".join(svc_parts)

                if state.lower() == 'open':
                    open_ports.append({"port": port_label, "state": state, "service": svc_str})
                    _svc_name = (service_el.get('name', '') if service_el is not None else '').lower()
                    if _svc_name in _RISKY_SERVICES:
                        _sev, _label = _RISKY_SERVICES[_svc_name]
                        _add_finding(_label, _sev, [], f"{port_label} open {svc_str}".strip(), port_label)

                for script_el in port_el.findall('script'):
                    _check_script(script_el, port_label)

            # Host-level (non-port) NSE scripts, e.g. hostscript-run checks
            for script_el in host.findall('hostscript/script'):
                _check_script(script_el)

        _cleartext_service_steps(findings)
        map_findings_list(findings)
        return findings, AssetInventory(target_ip=target_label, open_ports=open_ports)

    def _parse_grepable(self, content: str) -> Tuple[List[Finding], AssetInventory]:
        """Parses nmap's grepable output (-oG / .gnmap): one 'Host: <ip> (<hostname>)'
        line per host, with a tab-separated 'Ports: <id>/<state>/<proto>/<owner>/
        <service>/<rpc>/<version>/, ...' field.

        IMPORTANT LIMITATION (format, not a parsing bug): grepable format predates
        NSE scripts and structurally cannot carry script output at all, regardless of
        which -sC/--script flags were used during the actual scan. So unlike -oN/-oX,
        there is no NSE-derived vulnerability signal available here -- this can only
        recover the asset inventory (open ports + service/version banners). The
        keyword check below runs against those banners for defense-in-depth, but will
        rarely match anything real; if you need the same finding coverage as -oN/-oX,
        re-export the scan with -oN or -oX instead of (or alongside) -oG.
        """
        findings: List[Finding] = []
        open_ports: List[Dict[str, str]] = []
        target_label = "Target Host"
        seen_evidence = set()

        def _add_finding(title: str, severity: str, evidence: str, port_label: str = ""):
            ev_key = evidence.strip()
            # Keyed by host too -- see the XML path.
            key = (target_label, port_label, title, ev_key)
            if key in seen_evidence:
                return
            seen_evidence.add(key)
            findings.append(Finding(
                title=f"Nmap: {title}" + (f" ({port_label})" if port_label else ""),
                severity=severity,
                target=target_label,
                description=f"Nmap grepable-output service banner match on target {target_label}"
                            f"{(' port ' + port_label) if port_label else ''}: {ev_key}",
                remediation="Investigate service misconfiguration and apply vendor patches/hardening.",
                evidence=ev_key,
                source_tool="Nmap"
            ))

        for line in content.split('\n'):
            if not line.startswith('Host:'):
                continue
            m_host = re.match(r'^Host:\s+(\S+)\s*(?:\(([^)]*)\))?', line)
            if not m_host:
                continue
            ip = m_host.group(1)
            hostname = (m_host.group(2) or '').strip()
            target_label = f"{hostname} ({ip})" if hostname else ip

            m_ports = re.search(r'Ports:\s*(.+?)(?:\tIgnored State:|\t[A-Z][a-z]+:|$)', line)
            if not m_ports:
                continue

            for entry in re.split(r',\s*(?=\d+/)', m_ports.group(1).strip()):
                fields = entry.split('/')
                if len(fields) < 7:
                    continue
                portid, state, protocol = fields[0].strip(), fields[1].strip(), fields[2].strip()
                service, version = fields[4].strip(), fields[6].strip()
                if not portid or not protocol:
                    continue
                port_label = f"{portid}/{protocol}"
                svc_str = " ".join(x for x in [service, version] if x)

                if state.lower() == 'open':
                    open_ports.append({"port": port_label, "state": state, "service": svc_str})
                    if service.lower() in _RISKY_SERVICES:
                        _sev, _label = _RISKY_SERVICES[service.lower()]
                        _add_finding(_label, _sev, f"{port_label} open {svc_str}".strip(), port_label)

                for pattern, severity, label in _RISK_KEYWORDS:
                    if pattern.search(svc_str):
                        _add_finding(label, severity, svc_str, port_label)

        _cleartext_service_steps(findings)
        map_findings_list(findings)
        return findings, AssetInventory(target_ip=target_label, open_ports=open_ports)

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], AssetInventory]:
        content = content.replace('\r\n', '\n')

        # Native nmap XML export (-oX) -- distinct from the plain-text (-oN) console
        # output this parser previously only handled.
        stripped = content.strip()
        if stripped.startswith('<?xml') or stripped.startswith('<nmaprun'):
            findings, asset_inv = self._parse_xml(content)
            if findings or asset_inv.open_ports:
                return findings, asset_inv
            # Malformed/unrecognized XML -- fall through to plain-text parsing below
            # as a defensive last resort (harmless: won't match a real XML doc either).

        # Grepable output (-oG / .gnmap) -- structurally different line format from
        # both -oN and -oX, previously silently unhandled despite can_parse() claiming
        # support for the .gnmap extension.
        if re.search(r'^Host:\s+\S+.*Status:', content, re.MULTILINE):
            findings, asset_inv = self._parse_grepable(content)
            if asset_inv.open_ports:
                return findings, asset_inv
            # No parseable Host: lines found -- fall through as a defensive last resort.

        findings: List[Finding] = []
        open_ports: List[Dict[str, str]] = []
        # One finding per host, port and issue. The key used to be the evidence
        # text alone, so the same weakness on a second host -- identical script
        # output, different machine -- was discarded as a duplicate of the first.
        # A 399-host scan with the same five weaknesses on every host produced
        # ONE finding, attributed to the first host.
        by_key = {}
        scan_date = _scan_date(content)

        hosts = _split_hosts(content)
        target_ip = hosts[0][0] if hosts else "Target Host"
        if not hosts:
            hosts = [("Target Host", content)]

        def _add_finding(target, title, severity, cves, evidence, port_label=""):
            ev = evidence.strip()
            key = (target, port_label, _clean_nmap_title(title).lower(), tuple(sorted(c.upper() for c in cves)))
            if key in by_key:
                # The same issue seen again on the same port -- e.g. one
                # LUCKY13 line per CBC cipher. One finding, every line kept.
                f = by_key[key]
                if ev and ev not in f.evidence.split("\n"):
                    f.evidence = (f.evidence + "\n" + ev).strip()
                return f
            f = Finding(
                title=f"Nmap: {_clean_nmap_title(title)}" + (f" ({port_label})" if port_label else ""),
                severity=severity,
                cve_list=list(cves),
                target=target,
                # The matched line goes INTO the description, not just the
                # evidence field: map_finding_to_owasp() classifies on title +
                # description, and boilerplate alone sent every nmap finding to
                # the A05 default -- CVE-2013-0169 (Lucky13) was A05 here and A02
                # from the Nessus report in the same pack.
                description=f"Nmap detection on target {target}"
                            f"{(' port ' + port_label) if port_label else ''}: {ev}",
                remediation="Investigate service misconfiguration and apply vendor patches/hardening.",
                evidence=ev,
                source_tool="Nmap",
            )
            by_key[key] = f
            findings.append(f)
            return f

        # What each merged vulnerability finding affects on its port, so the
        # title can name them. One LUCKY13 finding per port replaced one per
        # cipher, and must not lose which ciphers they were: a title reduced to
        # the bare CVE is the defect test_kali_parser pins.
        affected = {}

        for target, section in hosts:
            ports = list(_PORT_LINE_RE.finditer(section))
            for idx, pm in enumerate(ports):
                port_label, state, service, version = pm.group(1), pm.group(2), pm.group(3), pm.group(4).strip()
                is_open = state.lower().startswith("open")
                if is_open:
                    open_ports.append({"port": port_label, "state": state,
                                       "service": f"{service} {version}".strip(), "host": target})
                block_end = ports[idx + 1].start() if idx + 1 < len(ports) else len(section)
                block = section[pm.end():block_end]
                # The port's own line is scanned too. Its version column is
                # where a CVE or weakness is written when the scan annotates the
                # service ("vsftpd 2.3.4 (Backdoor CVE-2011-2523)", "Redis
                # (unauthenticated access)"), and the scan window used to start
                # AFTER it -- so a file whose findings were all stated there
                # produced none.
                lines = [f"{service} {version}".strip()] + [
                    ln for ln in block.splitlines() if ln.strip()]

                # 1. CVE mentions -- the whole source line, so the title keeps
                #    the name that precedes the CVE token.
                for ln in lines:
                    cves = re.findall(r'CVE-\d{4}-\d{4,7}', ln, re.IGNORECASE)
                    if not cves:
                        continue
                    clean = ln.strip().lstrip('|_ ').strip()
                    named = re.search(r'vulnerable to\s+([A-Za-z0-9_-]+)', clean, re.IGNORECASE)
                    cves_u = sorted({c.upper() for c in cves})
                    title = (f"Vuln Finding: {named.group(1)} ({', '.join(cves_u)})" if named
                             else f"Vuln Finding: {clean[:90]}")
                    f = _add_finding(target, title, _severity_for_cve_line(clean, cves), cves_u,
                                     clean, port_label)
                    if named and f is not None:
                        ident = clean.split()[0]
                        ids = affected.setdefault(id(f), [])
                        if ident not in ids:
                            ids.append(ident)
                        shown = ", ".join(ids[:3]) + (f" +{len(ids) - 3} more" if len(ids) > 3 else "")
                        f.title = (f"Nmap: {_clean_nmap_title(title)} - {shown}"
                                   + (f" ({port_label})" if port_label else ""))

                # 2. Misconfiguration keywords in script output and the version column.
                for ln in lines:
                    stripped = ln.strip()
                    hits = [(sev, lab) for pat, sev, lab in _RISK_KEYWORDS if pat.search(stripped)]
                    labels = {lab for _s, lab in hits}
                    for severity, label in hits:
                        if _SUPERSEDED_BY.get(label) in labels:
                            continue
                        _add_finding(target, label, severity, [], stripped.lstrip('|_ '), port_label)

                # 3. Services that are a finding by being open at all.
                if is_open and service.lower() in _RISKY_SERVICES:
                    sev, label = _RISKY_SERVICES[service.lower()]
                    _add_finding(target, label, sev, [], f"{port_label} open {service} {version}".strip(),
                                 port_label)

                # 4. A certificate past its expiry at the time of the scan.
                m_exp = re.search(r'Not valid after:\s*(\d{4}-\d{2}-\d{2})', block)
                if m_exp and scan_date is not None:
                    try:
                        expired_on = datetime.strptime(m_exp.group(1), "%Y-%m-%d").date()
                    except ValueError:
                        expired_on = None
                    if expired_on is not None and expired_on < scan_date:
                        _add_finding(target, "SSL/TLS Certificate Expired", "MEDIUM", [],
                                     f"Not valid after: {expired_on.isoformat()} "
                                     f"(scan date {scan_date.isoformat()})", port_label)

        # Fallback general CVE scanner for OCR text / non-standard terminal blocks
        if not findings:
            for cm in re.finditer(r'\b(CVE-\d{4}-\d{4,7})\b\s*([^\n\r]{0,60})', content, re.IGNORECASE):
                cve_code = cm.group(1).upper()
                snippet = cm.group(0).strip()
                _add_finding(target_ip, f"Vulnerability {cve_code}",
                             _severity_for_cve_line(snippet, [cve_code]), [cve_code], snippet,
                             "Scanner Output")

        _cleartext_service_steps(findings)
        map_findings_list(findings)
        asset_inv = AssetInventory(target_ip=target_ip, open_ports=open_ports)
        return findings, asset_inv
