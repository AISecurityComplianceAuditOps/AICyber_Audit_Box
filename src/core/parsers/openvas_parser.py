# -*- coding: utf-8 -*-
"""
OpenVAS / Greenbone (GVM) report parser: the XML report format and the CSV
"Results" export.

The Qualys parser carried an OpenVAS branch, but its detection looked for a
bare "<result>" tag -- a real GVM report writes <result id="...">, every time
-- so an OpenVAS XML report was recognised by nobody and read as nothing, and
the CSV export was not handled at all. When the branch did run, its findings
were labelled "Qualys" and its CVE lookup read the pre-GVM-9 <cve> element,
where current reports list CVEs as <refs><ref type="cve" id="..."/>.

GVM rates each result itself ("High", "Medium", "Low", "Log"); that is the
severity, and <severity> is its CVSS score. "Log" results are the scanner's
notes (OS detected, services found) and are informational. QoD (quality of
detection) becomes the confidence.
"""
import csv
import io
import re
from typing import Any, List, Tuple

from .base_parser import BaseParser, is_image_file
from .finding_schema import Finding


def _severity(threat: str, score) -> str:
    t = str(threat or "").strip().lower()
    if t in ("critical", "high", "medium", "low"):
        return t.upper()
    if t in ("log", "debug", "none"):
        return "INFO"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "INFO"
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    return "LOW" if s > 0 else "INFO"


def _confidence(qod) -> str:
    try:
        q = int(float(qod))
    except (TypeError, ValueError):
        return "Firm"
    return "Certain" if q >= 95 else ("Firm" if q >= 70 else "Tentative")


def _score(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _target(ip: str, hostname: str, port: str) -> str:
    ip, hostname, port = (ip or "").strip(), (hostname or "").strip(), (port or "").strip()
    label = f"{hostname} ({ip})" if hostname and ip and hostname != ip else (hostname or ip or "Unknown Host")
    return f"{label}:{port}" if port and not port.startswith("general") else label


def _finding(name, threat, score, qod, ip, hostname, port, summary, insight, impact, specific,
             solution, cves, oid, vector=None) -> Finding:
    description = "\n\n".join(p for p in (summary, insight, impact) if p) or name
    if _severity(threat, score) == "INFO" and not solution:
        # "Log" results are the scanner's notes; there is nothing to fix.
        solution = "No action required; informational result recorded by the scanner."
    return Finding(
        title=name,
        severity=_severity(threat, score),
        severity_score=_score(score),
        cvss_vector=vector or None,
        cve_list=cves,
        target=_target(ip, hostname, port),
        description=description,
        remediation=solution or "Apply the vendor fix or mitigation described in the scanner result.",
        evidence=specific or summary or name,
        plugin_id=oid,
        confidence=_confidence(qod),
        source_tool="OpenVAS",
    )


class OpenVasParser(BaseParser):
    def can_parse(self, filename: str, content: str) -> bool:
        if not content or is_image_file(filename):
            return False
        return bool(self._kind(content))

    @staticmethod
    def _kind(content: str) -> str:
        head = content.lstrip()[:3000]
        if head.startswith("<") and re.search(r'<nvt oid="1\.3\.6\.1\.4\.1\.25623\.', content):
            return "xml"
        if head.startswith("<") and "<result id=" in content and "<nvt" in content and "<threat>" in content:
            return "xml"
        first = head.splitlines()[0] if head else ""
        if "NVT Name" in first and "NVT OID" in first:
            return "csv"
        return ""

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], Any]:
        findings = self._xml(content) if self._kind(content) == "xml" else self._csv(content)
        info = [f for f in findings if f.severity == "INFO"]
        for f in info:
            # Without this the shared mapper wraps it as "Apply the fix: No action required".
            f.remediation_actionable = f.remediation
        return [f for f in findings if f.severity != "INFO"], info

    @staticmethod
    def _xml(content: str) -> List[Finding]:
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(content.strip())
        except ET.ParseError:
            return []
        out, seen = [], set()
        for res in root.iter("result"):
            nvt = res.find("nvt")
            if nvt is None or res.get("id") in seen:
                continue
            seen.add(res.get("id"))
            threat = (res.findtext("threat") or "").strip()
            if threat.lower() == "false positive":
                continue
            host_el = res.find("host")
            ip = (host_el.text or "").strip() if host_el is not None else ""
            hostname = (host_el.findtext("hostname") or "").strip() if host_el is not None else ""
            tags = dict(t.split("=", 1) for t in (nvt.findtext("tags") or "").split("|") if "=" in t)
            cves = [r.get("id", "").upper() for r in nvt.iter("ref") if r.get("type", "").lower() == "cve"]
            legacy = (nvt.findtext("cve") or "").strip()                    # GVM <= 8
            if legacy and legacy.upper() != "NOCVE":
                cves += [c.upper() for c in re.findall(r'CVE-\d{4}-\d{4,7}', legacy, re.IGNORECASE)]
            vector = None
            sev_el = nvt.find("severities/severity")
            if sev_el is not None:
                vector = (sev_el.findtext("value") or "").strip() or None
            out.append(_finding(
                name=(res.findtext("name") or nvt.findtext("name") or "OpenVAS result").strip(),
                threat=threat,
                score=res.findtext("severity") or nvt.findtext("cvss_base"),
                qod=res.findtext("qod/value"),
                ip=ip, hostname=hostname, port=res.findtext("port") or "",
                summary=tags.get("summary", "").strip(),
                insight=tags.get("insight", "").strip(),
                impact=tags.get("impact", "").strip(),
                specific=(res.findtext("description") or "").strip(),
                solution=(nvt.findtext("solution") or tags.get("solution", "")).strip(),
                cves=sorted(set(cves)),
                oid=nvt.get("oid", ""),
                vector=vector or tags.get("cvss_base_vector"),
            ))
        return out

    @staticmethod
    def _csv(content: str) -> List[Finding]:
        out = []
        for row in csv.DictReader(io.StringIO(content.strip())):
            name = (row.get("NVT Name") or "").strip()
            if not name:
                continue
            port = (row.get("Port") or "").strip()
            proto = (row.get("Port Protocol") or "").strip()
            out.append(_finding(
                name=name,
                threat=row.get("Severity"),
                score=row.get("CVSS"),
                qod=row.get("QoD"),
                ip=row.get("IP", ""), hostname=row.get("Hostname", ""),
                port=f"{port}/{proto}" if port and proto else port,
                summary=(row.get("Summary") or "").strip(),
                insight=(row.get("Vulnerability Insight") or "").strip(),
                impact=(row.get("Impact") or "").strip(),
                specific=(row.get("Specific Result") or "").strip(),
                solution=(row.get("Solution") or "").strip(),
                cves=sorted({c.upper() for c in re.findall(r'CVE-\d{4}-\d{4,7}', row.get("CVEs") or "", re.IGNORECASE)}),
                oid=(row.get("NVT OID") or "").strip(),
            ))
        return out
