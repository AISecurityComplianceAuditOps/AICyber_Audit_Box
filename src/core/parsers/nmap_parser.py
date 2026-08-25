# -*- coding: utf-8 -*-
import re
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
]

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
            if ev_key in seen_evidence:
                return
            seen_evidence.add(ev_key)
            findings.append(Finding(
                title=f"Nmap: {title}" + (f" ({port_label})" if port_label else ""),
                severity=severity,
                cve_list=cves,
                target=target_label,
                description=f"Nmap NSE script detection on target {target_label}"
                            f"{(' port ' + port_label) if port_label else ''}.",
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

                for script_el in port_el.findall('script'):
                    _check_script(script_el, port_label)

            # Host-level (non-port) NSE scripts, e.g. hostscript-run checks
            for script_el in host.findall('hostscript/script'):
                _check_script(script_el)

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
            if ev_key in seen_evidence:
                return
            seen_evidence.add(ev_key)
            findings.append(Finding(
                title=f"Nmap: {title}" + (f" ({port_label})" if port_label else ""),
                severity=severity,
                target=target_label,
                description=f"Nmap grepable-output service banner match on target {target_label}"
                            f"{(' port ' + port_label) if port_label else ''}.",
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

                for pattern, severity, label in _RISK_KEYWORDS:
                    if pattern.search(svc_str):
                        _add_finding(label, severity, svc_str, port_label)

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
        target_ip = "Target Host"
        seen_evidence = set()

        m_ip = re.search(r'Nmap scan report for\s+([^\n]+)', content, re.IGNORECASE)
        if m_ip:
            target_ip = m_ip.group(1).strip()

        # Per-port blocks: each port header line through to the next port header (or EOF)
        # so NSE script hits below a port can be attributed to that port/service.
        port_header_re = re.compile(r'\b(\d+/(?:tcp|udp))\s+(\w+)\s+([^\n\r]{0,60})', re.IGNORECASE)
        port_matches = list(port_header_re.finditer(content))

        for pm in port_matches:
            port, state, svc = pm.group(1), pm.group(2), pm.group(3)
            if state.lower() == "open":
                open_ports.append({"port": port, "state": state, "service": svc.strip()})

        def _add_finding(title: str, severity: str, cves: List[str], evidence: str, port_label: str = ""):
            ev_key = evidence.strip()
            if ev_key in seen_evidence:
                return
            seen_evidence.add(ev_key)
            findings.append(Finding(
                title=f"Nmap: {title}" + (f" ({port_label})" if port_label else ""),
                severity=severity,
                cve_list=cves,
                target=target_ip,
                description=f"Nmap NSE script detection on target {target_ip}"
                            f"{(' port ' + port_label) if port_label else ''}.",
                remediation="Investigate service misconfiguration and apply vendor patches/hardening.",
                evidence=ev_key,
                source_tool="Nmap"
            ))

        for idx, pm in enumerate(port_matches):
            port_label = pm.group(1)
            block_start = pm.end()
            block_end = port_matches[idx + 1].start() if idx + 1 < len(port_matches) else len(content)
            block = content[block_start:block_end]

            # 1. Explicit NSE "-vuln" scripts / CVE mentions
            nse_hits = re.findall(r'(?:\|_?)?([a-zA-Z0-9_-]+-vuln[^\n]*|\bCVE-\d{4}-\d+\b[^\n]*)', block, re.IGNORECASE)
            for hit in nse_hits:
                if hit and len(hit.strip()) > 3:
                    cves = re.findall(r'CVE-\d{4}-\d{4,7}', hit, re.IGNORECASE)
                    if cves:
                        _add_finding(f"Vuln Finding: {hit[:60]}", "HIGH" if cves else "MEDIUM", cves, hit, port_label)

            # 2. Keyword-based misconfiguration detection across NSE script lines in the block
            for line in block.splitlines():
                stripped = line.strip()
                for pattern, severity, label in _RISK_KEYWORDS:
                    if pattern.search(stripped):
                        _add_finding(label, severity, [], stripped.lstrip('|_ '), port_label)

        # Fallback general CVE scanner for OCR text / non-standard terminal blocks
        if not findings:
            cve_matches = list(re.finditer(r'\b(CVE-\d{4}-\d{4,7})\b\s*([^\n\r]{0,60})', content, re.IGNORECASE))
            for cm in cve_matches:
                cve_code = cm.group(1).upper()
                snippet = cm.group(0).strip()
                _add_finding(f"Vulnerability {cve_code}", "HIGH", [cve_code], snippet, "Scanner Output")

        map_findings_list(findings)
        asset_inv = AssetInventory(target_ip=target_ip, open_ports=open_ports)
        return findings, asset_inv
