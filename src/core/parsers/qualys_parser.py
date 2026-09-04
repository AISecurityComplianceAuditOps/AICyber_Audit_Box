# -*- coding: utf-8 -*-
import csv
import io
import re
from typing import List, Tuple, Optional
from bs4 import BeautifulSoup
from .base_parser import BaseParser, is_image_file

# Prefer lxml for speed; fallback to html.parser if unavailable
try:
    import lxml  # noqa: F401
    _HTML_PARSER = "lxml"
    _XML_PARSER = "lxml-xml"
except ImportError:
    _HTML_PARSER = "html.parser"
    _XML_PARSER = "html.parser"
from .finding_schema import Finding
from .control_mapper import map_findings_list

# Qualys' standard numeric severity scale (1-5). Different report templates label
# these differently (Urgent/Critical/Serious/Medium/Minimal etc.) but the 1-5
# numeric scale itself is stable across Qualys deployments.
QUALYS_SEVERITY_MAP = {
    "5": "CRITICAL",
    "4": "HIGH",
    "3": "MEDIUM",
    "2": "LOW",
    "1": "INFO",
}

# CSV export column names vary slightly between Qualys report templates
# (custom templates can rename/reorder columns) -- match case-insensitively
# against known aliases rather than a single fixed header name.
COLUMN_ALIASES = {
    "qid": ["qid"],
    "title": ["title", "vulnerability title"],
    "severity": ["severity"],
    "cve": ["cve id", "cve", "cve ids"],
    "solution": ["solution", "remediation"],
    "threat": ["threat", "impact", "description", "vulnerability description"],
    "ip": ["ip", "ip address"],
    "dns": ["dns", "fqdn", "netbios"],
    "port": ["port"],
    "protocol": ["protocol"],
    "cvss": ["cvss3.1", "cvss3", "cvss", "cvss base", "cvss3.1 base"],
}


def _find_col(headers_norm: dict, key: str) -> Optional[str]:
    for alias in COLUMN_ALIASES[key]:
        if alias in headers_norm:
            return headers_norm[alias]
    return None


class QualysParser(BaseParser):
    """Parses Qualys / OpenVAS vulnerability scan exports.
    Primary support: Qualys CSV export (the most common real-world export format).
    XML support covers three real-world layouts, tried in order:
      1. Qualys 'Host List Detection' XML (the actual format Qualys's API/UI export --
         <HOST><DETECTION_LIST><DETECTION> with a separate <GLOSSARY> for titles).
      2. Simpler/legacy Qualys <VULN> XML variant (title inline, no glossary).
      3. OpenVAS/Greenbone GMP <result> XML.
    NOTE: still not verified against a real customer export file -- built against
    each tool's documented/published schema and synthetic samples matching it. If a
    real export doesn't parse, compare its actual structure against the three
    _parse_qualys_detection_xml / _parse_qualys_vuln_xml / _parse_openvas_gmp_xml
    methods below and adjust the one that's closest.
    """

    def can_parse(self, filename: str, content: str) -> bool:
        """Content-signature based detection — 0% filename keyword dependency.
        Rejects image files immediately, then inspects structural content
        exclusive to Qualys / OpenVAS exports.
        """
        if not content:
            return False
        # Guard: reject image files regardless of their filename.
        if is_image_file(filename):
            return False
        # Content-signature: QID is Qualys-exclusive column / XML tag.
        # OpenVAS/Greenbone GMP XML has a distinctive <result> / <nvt> structure.
        # Scans the FULL content, not a fixed-size prefix -- see burp_parser.py/
        # nessus_parser.py for the real-world case (a large embedded stylesheet
        # pushing signal content past a fixed sample window) that surfaced this
        # class of bug.
        sample = content.lower()
        # "qid" checked with word boundaries -- as a bare substring it could match
        # inside unrelated tokens (e.g. a URL query-string param literally named
        # "qid=" in some other tool's export) rather than genuinely indicating the
        # Qualys-specific QID column/tag.
        if (re.search(r'\bqid\b', sample)
                or "qualys" in sample
                or "<host_list>" in sample
                or "<detection_list>" in sample
                or "openvas" in sample
                or ("<result>" in sample and "<nvt" in sample)):
            return True
        return False

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], None]:
        stripped = content.lstrip()
        if stripped.startswith("<"):
            findings = self._parse_xml(content)
        else:
            findings = self._parse_csv(content)

        map_findings_list(findings)
        if not findings:
            print(f"[QUALYS PARSER WARNING] Recognized '{filename}' as a Qualys/OpenVAS file but extracted "
                  f"0 findings -- format may not match the supported CSV/XML structure. Needs review.", flush=True)
        else:
            print(f"[QUALYS PARSER] Extracted {len(findings)} finding(s) from '{filename}'.", flush=True)
        return findings, None

    # ── CSV export (primary path) ──────────────────────────────────────────
    def _parse_csv(self, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            reader = csv.DictReader(io.StringIO(content))
            if not reader.fieldnames:
                return []
            headers_norm = {h.strip().lower(): h for h in reader.fieldnames if h}

            col_title = _find_col(headers_norm, "title")
            col_sev = _find_col(headers_norm, "severity")
            col_cve = _find_col(headers_norm, "cve")
            col_solution = _find_col(headers_norm, "solution")
            col_threat = _find_col(headers_norm, "threat")
            col_ip = _find_col(headers_norm, "ip")
            col_dns = _find_col(headers_norm, "dns")
            col_port = _find_col(headers_norm, "port")
            col_qid = _find_col(headers_norm, "qid")
            col_cvss = _find_col(headers_norm, "cvss")

            if not col_title and not col_qid:
                # Doesn't look like a Qualys CSV export at all
                return []

            for row in reader:
                title = (row.get(col_title) or "").strip() if col_title else ""
                qid = (row.get(col_qid) or "").strip() if col_qid else ""
                if not title and not qid:
                    continue
                if not title:
                    title = f"Qualys QID {qid}"

                raw_sev = (row.get(col_sev) or "").strip() if col_sev else ""
                sev_digits = re.sub(r"[^0-9]", "", raw_sev)
                severity = QUALYS_SEVERITY_MAP.get(sev_digits, raw_sev or "INFO")

                cve_raw = (row.get(col_cve) or "").strip() if col_cve else ""
                cve_list = [c.strip() for c in re.split(r"[,;\s]+", cve_raw) if c.strip().upper().startswith("CVE-")]

                ip = (row.get(col_ip) or "").strip() if col_ip else ""
                dns = (row.get(col_dns) or "").strip() if col_dns else ""
                port = (row.get(col_port) or "").strip() if col_port else ""
                target = " / ".join(p for p in [ip, dns] if p) or "Unknown Host"
                if port:
                    target = f"{target}:{port}"

                cvss_score = None
                if col_cvss:
                    try:
                        cvss_score = float((row.get(col_cvss) or "").strip())
                    except (ValueError, TypeError):
                        cvss_score = None

                findings.append(Finding(
                    title=title,
                    severity=severity,
                    severity_score=cvss_score,
                    cve_list=cve_list,
                    target=target,
                    description=(row.get(col_threat) or "").strip() if col_threat else title,
                    remediation=(row.get(col_solution) or "").strip() if col_solution else "Apply vendor patch per Qualys solution guidance.",
                    evidence=f"QID {qid}" if qid else "",
                    plugin_id=qid,
                    source_tool="Qualys",
                ))
        except Exception as e:
            print(f"[QUALYS PARSER ERROR] CSV parsing failed: {e}", flush=True)
            return []
        return findings

    # ── XML export (best-effort secondary path — Qualys XML / OpenVAS GMP XML) ──
    def _parse_xml(self, content: str) -> List[Finding]:
        try:
            soup = BeautifulSoup(content, _XML_PARSER)
        except Exception:
            soup = None
        if soup is None:
            try:
                soup = BeautifulSoup(content, _HTML_PARSER)
            except Exception:
                return []

        findings = self._parse_qualys_detection_xml(soup)
        if findings:
            return findings

        findings = self._parse_qualys_vuln_xml(soup)
        if findings:
            return findings

        return self._parse_openvas_gmp_xml(soup)

    def _parse_qualys_detection_xml(self, soup) -> List[Finding]:
        """Qualys 'Host List Detection' XML (the real format Qualys's API/UI actually
        exports): <HOST_LIST><HOST><IP>/<DNS>/<DETECTION_LIST><DETECTION><QID>/<SEVERITY>/
        <RESULTS>...</DETECTION></DETECTION_LIST></HOST></HOST_LIST>, with vulnerability
        titles kept separately in a <GLOSSARY><QID_LIST><QID><QID>id</QID><TITLE>...
        </QID></QID_LIST></GLOSSARY> lookup table rather than inline per-detection."""
        findings: List[Finding] = []

        qid_titles = {}
        for qid_node in soup.find_all(re.compile(r"^qid$", re.IGNORECASE)):
            parent = qid_node.parent
            if parent is not None and parent.name and parent.name.lower() == "qid":
                inner_qid = qid_node.get_text(strip=True)
                title_node = parent.find(re.compile(r"^title$", re.IGNORECASE))
                if inner_qid and title_node:
                    qid_titles[inner_qid] = title_node.get_text(strip=True)

        for host in soup.find_all(re.compile(r"^host$", re.IGNORECASE)):
            ip_node = host.find(re.compile(r"^ip$", re.IGNORECASE))
            dns_node = host.find(re.compile(r"^dns$", re.IGNORECASE))
            ip = ip_node.get_text(strip=True) if ip_node else ""
            dns = dns_node.get_text(strip=True) if dns_node else ""
            base_target = " / ".join(p for p in [ip, dns] if p) or "Unknown Host"

            for det in host.find_all(re.compile(r"^detection$", re.IGNORECASE)):
                def _text(tag_name):
                    t = det.find(re.compile(f"^{tag_name}$", re.IGNORECASE))
                    return t.get_text(strip=True) if t else ""

                qid = _text("qid")
                if not qid:
                    continue
                title = qid_titles.get(qid) or _text("title") or f"Qualys QID {qid}"

                raw_sev = _text("severity")
                sev_digits = re.sub(r"[^0-9]", "", raw_sev)
                severity = QUALYS_SEVERITY_MAP.get(sev_digits, raw_sev or "INFO")

                results_text = _text("results")
                port = _text("port")
                target = f"{base_target}:{port}" if port else base_target

                findings.append(Finding(
                    title=title,
                    severity=severity,
                    target=target,
                    description=results_text or title,
                    remediation="Apply vendor patch per Qualys solution guidance.",
                    evidence=results_text[:500] if results_text else f"QID {qid}",
                    plugin_id=qid,
                    source_tool="Qualys",
                ))
        return findings

    def _parse_qualys_vuln_xml(self, soup) -> List[Finding]:
        """Simpler/legacy Qualys XML variant: <VULN><QID>/<TITLE>/<SEVERITY>... with a
        preceding sibling <IP> giving the host, no separate glossary needed."""
        findings: List[Finding] = []
        vuln_nodes = soup.find_all(re.compile(r"^vuln$", re.IGNORECASE))

        for node in vuln_nodes:
            def _text(tag_name):
                t = node.find(re.compile(f"^{tag_name}$", re.IGNORECASE))
                return t.get_text(strip=True) if t else ""

            title = _text("title") or "Qualys Finding"
            qid = _text("qid")
            raw_sev = _text("severity")
            sev_digits = re.sub(r"[^0-9]", "", raw_sev)
            severity = QUALYS_SEVERITY_MAP.get(sev_digits, raw_sev or "INFO")

            cve_text = _text("cve") or _text("cve_id")
            cve_list = [c.strip() for c in re.split(r"[,;\s]+", cve_text) if c.strip().upper().startswith("CVE-")]

            threat = _text("threat") or _text("description") or _text("diagnosis")
            solution = _text("solution") or _text("recommendation") or "Apply vendor patch per scanner solution guidance."

            ip_node = node.find_previous(re.compile(r"^ip$", re.IGNORECASE))
            target = ip_node.get_text(strip=True) if ip_node else "Unknown Host"

            if not title and not qid and not cve_list:
                continue

            findings.append(Finding(
                title=title,
                severity=severity,
                cve_list=cve_list,
                target=target,
                description=threat or title,
                remediation=solution,
                evidence=f"QID {qid}" if qid else "",
                plugin_id=qid,
                source_tool="Qualys",
            ))
        return findings

    def _parse_openvas_gmp_xml(self, soup) -> List[Finding]:
        """OpenVAS/Greenbone GMP <get_reports> XML: <result><name>/<host>/<port>/
        <severity> (a numeric CVSS-like score, NOT the 1-5 Qualys scale) /<threat>
        (word form: High/Medium/Low/Log/None) /<nvt><cve>...</nvt></result>.

        Bug fixed here: previously ran the numeric <severity> score straight through
        QUALYS_SEVERITY_MAP (keys "1".."5"), so an OpenVAS score like "7.5" stripped
        to digits ("75") never matched and silently fell back to raw text "7.5" as
        the severity string -- which Finding.__post_init__ then normalizes to INFO,
        since "7.5" contains no CRIT/HIGH/MED/LOW substring. A genuine HIGH-severity
        finding was being mislabeled INFO. Now prefers the word-form <threat>, and
        falls back to proper CVSS-score-band mapping (not digit-stripping) for the
        numeric <severity> when <threat> is absent.
        """
        findings: List[Finding] = []
        result_nodes = soup.find_all(re.compile(r"^result$", re.IGNORECASE))

        for node in result_nodes:
            def _text(tag_name):
                t = node.find(re.compile(f"^{tag_name}$", re.IGNORECASE))
                return t.get_text(strip=True) if t else ""

            title = _text("name") or "OpenVAS Finding"
            threat = _text("threat")
            raw_score = _text("severity")

            cvss_score = None
            if raw_score:
                try:
                    cvss_score = float(raw_score)
                except ValueError:
                    cvss_score = None

            if threat and threat.upper() not in ("LOG", "NONE", ""):
                severity = threat.upper()
            elif cvss_score is not None:
                if cvss_score >= 9.0: severity = "CRITICAL"
                elif cvss_score >= 7.0: severity = "HIGH"
                elif cvss_score >= 4.0: severity = "MEDIUM"
                elif cvss_score > 0.0: severity = "LOW"
                else: severity = "INFO"
            else:
                severity = "INFO"

            nvt_node = node.find(re.compile(r"^nvt$", re.IGNORECASE))
            cve_text = (nvt_node.find(re.compile(r"^cve$", re.IGNORECASE)).get_text(strip=True)
                        if nvt_node and nvt_node.find(re.compile(r"^cve$", re.IGNORECASE)) else "") or _text("cve")
            cve_list = [c.strip() for c in re.split(r"[,;\s]+", cve_text) if c.strip().upper().startswith("CVE-")]

            host = _text("host")
            port = _text("port")
            target = f"{host}:{port}" if host and port else (host or "Unknown Host")

            description = _text("description") or title
            solution_node = node.find(re.compile(r"^solution$", re.IGNORECASE))
            solution = solution_node.get_text(strip=True) if solution_node else "Apply vendor patch per scanner solution guidance."

            if not title:
                continue

            findings.append(Finding(
                title=title,
                severity=severity,
                severity_score=cvss_score,
                cve_list=cve_list,
                target=target,
                description=description,
                remediation=solution,
                evidence="",
                source_tool="Qualys",
            ))
        return findings
