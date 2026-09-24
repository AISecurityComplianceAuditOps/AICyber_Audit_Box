# -*- coding: utf-8 -*-
"""
OWASP ZAP report parser: the XML (-x / "Traditional XML Report") and JSON
(-J / "Traditional JSON Report") exports.

Before this parser a ZAP XML report was claimed by BurpParser -- whose
detection accepts "<OWASPZAPReport" -- and read as nothing, and a ZAP JSON
report fell through to the Burp fallback, which scraped "SQL Injection" out of
the text three times as "Visual PoC" findings against "Web Application
Endpoint". Neither kept a single field of what ZAP reported.

ZAP groups every URL an alert fired on under that alert. One alert is one
finding; its URLs are the target (when there is one) or listed in the
evidence (when there are several), so a missing header on fifty pages is one
finding, not fifty.
"""
import html
import json
import re
from typing import Any, List, Tuple

from .base_parser import BaseParser, is_image_file
from .finding_schema import Finding

# riskcode: 0 Informational, 1 Low, 2 Medium, 3 High.
_RISK = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}
# confidence: 0 False Positive, 1 Low, 2 Medium, 3 High, 4 User Confirmed.
_CONFIDENCE = {"1": "Tentative", "2": "Firm", "3": "Certain", "4": "Certain"}


def _plain(text: str) -> str:
    """ZAP's desc/solution/reference fields are HTML fragments."""
    text = html.unescape(str(text or ""))
    text = re.sub(r'</p>\s*<p>|<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    return re.sub(r'[ \t]+', ' ', text).strip()


def _alert_finding(alert: dict, site: str) -> Finding:
    riskcode = str(alert.get("riskcode", "")).strip()
    confidence = str(alert.get("confidence", "")).strip()
    name = str(alert.get("alert") or alert.get("name") or "ZAP alert").strip()
    instances = [i for i in alert.get("instances") or [] if isinstance(i, dict)]
    uris = []
    for inst in instances:
        u = str(inst.get("uri", "")).strip()
        p = str(inst.get("param", "")).strip()
        label = f"{u} [{p}]" if p else u
        if label and label not in uris:
            uris.append(label)
    target = uris[0] if len(uris) == 1 else site
    cwe = str(alert.get("cweid", "")).strip()
    cwes = [f"CWE-{cwe}"] if cwe.isdigit() and int(cwe) > 0 else []
    desc = _plain(alert.get("desc"))
    other = _plain(alert.get("otherinfo"))
    evidence_lines = []
    for inst in instances[:10]:
        bits = [str(inst.get("method", "")).strip(), str(inst.get("uri", "")).strip()]
        for key in ("param", "attack", "evidence"):
            v = str(inst.get(key, "")).strip()
            if v:
                bits.append(f"{key}: {v}")
        evidence_lines.append(" ".join(b for b in bits if b))
    if len(instances) > 10:
        evidence_lines.append(f"... and {len(instances) - 10} more instance(s)")
    return Finding(
        title=name,
        severity=_RISK.get(riskcode, "INFO"),
        cve_list=cwes,
        target=target,
        description=(desc + (f"\n\n{other}" if other else "")
                     + (f"\n\nFound on {len(uris)} URL(s)." if len(uris) > 1 else "")).strip(),
        remediation=_plain(alert.get("solution")),
        evidence="\n".join(evidence_lines) or name,
        plugin_id=str(alert.get("pluginid", "")),
        confidence=_CONFIDENCE.get(confidence, "Firm"),
        source_tool="OWASP ZAP",
    )


class ZapParser(BaseParser):
    def can_parse(self, filename: str, content: str) -> bool:
        if not content or is_image_file(filename):
            return False
        head = content[:4000]
        if "<OWASPZAPReport" in head:
            return True
        return '"@programName"' in head and '"ZAP"' in head.replace(" ", "") and '"site"' in content

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], Any]:
        sites = self._sites_xml(content) if content.lstrip().startswith("<") else self._sites_json(content)
        findings = []
        for site, alerts in sites:
            for alert in alerts:
                # confidence 0 is ZAP's "False Positive": the tester dismissed it.
                if str(alert.get("confidence", "")).strip() == "0":
                    continue
                findings.append(_alert_finding(alert, site))
        actionable = [f for f in findings if f.severity != "INFO"]
        info = [f for f in findings if f.severity == "INFO"]
        return actionable, info

    @staticmethod
    def _sites_json(content: str):
        try:
            data = json.loads(content)
        except ValueError:
            return []
        sites = data.get("site") or []
        sites = sites if isinstance(sites, list) else [sites]
        return [(str(s.get("@name", "")), [a for a in s.get("alerts") or [] if isinstance(a, dict)])
                for s in sites if isinstance(s, dict)]

    @staticmethod
    def _sites_xml(content: str):
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(content.strip())
        except ET.ParseError:
            return []
        out = []
        for site in root.iter("site"):
            alerts = []
            for item in site.iter("alertitem"):
                alert = {child.tag: (child.text or "") for child in item if child.tag != "instances"}
                alert["instances"] = [
                    {c.tag: (c.text or "") for c in inst}
                    for inst in item.iter("instance")
                ]
                # ZAP before 2.8 wrote one <uri>/<param> per alertitem, no <instances>.
                if not alert["instances"] and alert.get("uri"):
                    alert["instances"] = [{k: alert.get(k, "") for k in ("uri", "method", "param", "attack", "evidence")}]
                alerts.append(alert)
            out.append((site.get("name", ""), alerts))
        return out
