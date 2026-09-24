# -*- coding: utf-8 -*-
"""
ProjectDiscovery nuclei parser: console output, -jsonl (one JSON object per
line, "-json" before v3) and -json-export (one JSON array).

Nothing read nuclei output before this: a scan confirming CVE-2021-41773 (path
traversal to RCE in Apache 2.4.49) and an exposed .git/config produced zero
findings in every format.

nuclei rates each template itself (info/low/medium/high/critical); that
rating is the finding's severity. The JSON formats also carry the template's
name, description, remediation, references, CVE/CWE and CVSS; the console
format carries only the template id, severity and URL, and says so.
"""
import json
import re
from typing import Any, List, Tuple

from .base_parser import BaseParser, is_image_file
from .finding_schema import Finding

_SEVERITIES = ("info", "low", "medium", "high", "critical", "unknown")
# [2025-06-24 10:00:00] [template-id:matcher] [http] [critical] URL ["extracted"]
_CONSOLE_RE = re.compile(
    r'^(?:\[[\d:\- T.Z+]+\]\s+)?\[(?P<tid>[\w.:/-]+)\]\s+\[(?P<proto>[a-z]+)\]\s+'
    r'\[(?P<sev>' + "|".join(_SEVERITIES) + r')\]\s+(?P<url>\S+)(?P<rest>.*)$',
    re.MULTILINE | re.IGNORECASE)


def _sev(value: str) -> str:
    v = str(value or "").strip().lower()
    return "INFO" if v in ("info", "unknown", "") else v.upper()


def _json_records(content: str) -> List[dict]:
    s = content.strip()
    if s.startswith("["):
        try:
            data = json.loads(s)
            return [r for r in data if isinstance(r, dict)]
        except ValueError:
            return []
    out = []
    for line in s.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
    return out


def _fallback_fix(tid: str, tags: List[str], cves: List[str], extra: str = "") -> str:
    """What to do when the template ships no remediation of its own. Most
    exposure and detection templates carry none; "Remediate the issue
    identified by template X" told the reader nothing."""
    words = " ".join([tid] + list(tags)).lower()
    if cves:
        return f"Apply the vendor's security update that fixes {', '.join(cves)} for the affected product."
    if re.search(r'default-login|default-cred|weak-login', words):
        return "Change the default credentials and disable any default accounts."
    if re.search(r'takeover', words):
        return "Remove the dangling DNS record or reclaim the third-party resource it points to."
    if re.search(r'missing-security-headers|security-headers', words):
        header = extra or "the missing security header"
        return f"Send {header} on every HTTP response."
    if re.search(r'exposure|exposed|\bgit\b|git-|\.git|config|backup|\blogs?\b|\benv\b|dotenv|\bfiles?\b', words):
        return ("Remove the exposed file or directory from the web root, or deny access to it at the web server, "
                "and rotate any secret it contained.")
    if re.search(r'\btech\b|detect|fingerprint|version', words):
        return "No action required; the detected technology is recorded for the asset inventory."
    if re.search(r'misconfig', words):
        return "Correct the misconfiguration described by the finding."
    return f"Review and remediate the issue reported by nuclei template '{tid}'."


def _is_nuclei_record(rec: dict) -> bool:
    return ("template-id" in rec or "templateID" in rec) and isinstance(rec.get("info"), dict)


class NucleiParser(BaseParser):
    def can_parse(self, filename: str, content: str) -> bool:
        if not content or is_image_file(filename):
            return False
        s = content.lstrip()
        if s[:1] in "[{" and ('"template-id"' in content or '"templateID"' in content):
            return any(_is_nuclei_record(r) for r in _json_records(content)[:5])
        return bool(_CONSOLE_RE.search(content))

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], Any]:
        records = [r for r in _json_records(content) if _is_nuclei_record(r)] if content.lstrip()[:1] in "[{" else []
        findings = ([self._from_json(r) for r in records] if records
                    else [self._from_console(m) for m in _CONSOLE_RE.finditer(content)])
        # One finding per template per matched location.
        seen, out = set(), []
        for f in findings:
            key = (f.plugin_id, f.target, f.title)
            if key not in seen:
                seen.add(key)
                out.append(f)
        info = [f for f in out if f.severity == "INFO"]
        for f in info:
            if not f.remediation_actionable:
                f.remediation_actionable = f.remediation
        return [f for f in out if f.severity != "INFO"], info

    @staticmethod
    def _from_json(rec: dict) -> Finding:
        info = rec.get("info") or {}
        tid = str(rec.get("template-id") or rec.get("templateID") or "")
        cls = info.get("classification") or {}
        cves = [str(c).upper() for c in (cls.get("cve-id") or []) if c]
        cwes = [str(c).upper() for c in (cls.get("cwe-id") or []) if c]
        if not cves and re.match(r'CVE-\d{4}-\d{4,7}$', tid, re.IGNORECASE):
            cves = [tid.upper()]
        score = cls.get("cvss-score")
        try:
            score = float(score) if score not in (None, "") else None
        except (TypeError, ValueError):
            score = None
        matched = str(rec.get("matched-at") or rec.get("matched") or rec.get("host") or "")
        extracted = rec.get("extracted-results") or []
        refs = info.get("reference") or []
        refs = refs if isinstance(refs, list) else [refs]
        name = str(info.get("name") or tid)
        matcher = str(rec.get("matcher-name") or "")
        tags = info.get("tags") or []
        tags = tags if isinstance(tags, list) else str(tags).split(",")
        own = str(info.get("remediation") or "").strip()
        remediation = own or _fallback_fix(tid, tags, cves, matcher)
        return Finding(
            # A CVE in a vendor product is fixed by the vendor's update. Left to
            # the shared mapper, CWE-22 on Apache's CVE-2021-41773 produced
            # "sanitize file path inputs" -- advice for code the site does not own.
            remediation_actionable=(
                f"1. {remediation} 2. Re-run nuclei with template '{tid}' against {rec.get('host') or 'the target'} "
                f"and confirm it no longer matches." if (cves and own) else ""),
            title=f"{name} ({', '.join(cves)})" if cves and cves[0] not in name else name,
            severity=_sev(info.get("severity")),
            severity_score=score,
            cvss_vector=str(cls.get("cvss-metrics") or "") or None,
            cve_list=cves + [c for c in cwes if c not in cves],
            target=matched,
            description=str(info.get("description") or name).strip(),
            remediation=remediation,
            evidence="\n".join(filter(None, [
                f"template: {tid}" + (f":{matcher}" if matcher else ""),
                f"matched-at: {matched}",
                ("extracted: " + ", ".join(map(str, extracted))) if extracted else "",
                ("references: " + ", ".join(map(str, refs[:5]))) if refs else "",
            ])),
            plugin_id=tid,
            source_tool="Nuclei",
        )

    @staticmethod
    def _from_console(m) -> Finding:
        tid = m.group("tid")
        base = tid.split(":", 1)[0]
        cves = [base.upper()] if re.match(r'CVE-\d{4}-\d{4,7}$', base, re.IGNORECASE) else []
        return Finding(
            title=f"nuclei: {tid}",
            severity=_sev(m.group("sev")),
            cve_list=cves,
            target=m.group("url"),
            description=(f"nuclei template '{tid}' ({m.group('proto')}) matched at {m.group('url')}. "
                         f"The console output carries no description; export with -jsonl for the "
                         f"template's full details."),
            remediation=_fallback_fix(base, [], cves, tid.split(":", 1)[1] if ":" in tid else ""),
            evidence=m.group(0).strip(),
            plugin_id=base,
            source_tool="Nuclei",
        )
