# -*- coding: utf-8 -*-
"""
Code and dependency scanner exports: SARIF 2.x (CodeQL, Semgrep, Trivy -f sarif,
Checkov, gitleaks, Snyk Code...), Grype JSON, npm audit JSON (v1 and v2),
gitleaks JSON, Bandit JSON, and any JSON holding a list of findings with a
severity and a title or rule (a CI security pipeline's own report, for one).

None of these was read before. A real DevSecOps pipeline report among the
evidence on file -- five dependency CVEs (PyJWT, langchain-ollama, pgvector,
reportlab) -- produced no findings, as did every format above.

Severity is the tool's own. SARIF's "security-severity" is a CVSS-style score
and is used when present; otherwise the result "level" (error / warning /
note). gitleaks rates nothing; a committed secret is reported as HIGH and the
finding says the rating is the auditor's call. Secrets are never copied into
the finding.
"""
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from .base_parser import BaseParser, is_image_file
from .finding_schema import Finding, full_poc

_SEV_WORDS = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "moderate": "MEDIUM",
    "low": "LOW", "info": "INFO", "informational": "INFO", "information": "INFO",
    "negligible": "INFO", "unknown": "INFO", "none": "INFO",
    "error": "HIGH", "warning": "MEDIUM", "note": "LOW",
}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE[-_ ]?(\d{1,5})", re.IGNORECASE)


def _sev(value) -> Optional[str]:
    return _SEV_WORDS.get(str(value or "").strip().lower())


def _band(score) -> Optional[str]:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    return "LOW" if s > 0 else "INFO"


def _cwes(*texts) -> List[str]:
    out = []
    for t in texts:
        for n in _CWE_RE.findall(str(t or "")):
            c = f"CWE-{int(n)}"
            if c not in out:
                out.append(c)
    return out


def _cves(*texts) -> List[str]:
    out = []
    for t in texts:
        for c in _CVE_RE.findall(str(t or "")):
            if c.upper() not in out:
                out.append(c.upper())
    return out


def _load(content: str):
    s = (content or "").strip()
    if not s or s[0] not in "[{":
        return None
    try:
        return json.loads(s)
    except ValueError:
        return None


# ── generic findings lists ───────────────────────────────────────────────────
_TITLE_KEYS = ("title", "name", "vulnerability", "issue", "check_name", "rule_name", "test_name")
_RULE_KEYS = ("rule", "rule_id", "ruleid", "check_id", "test_id", "id", "vulnerability_id", "cve")
_DESC_KEYS = ("description", "details", "message", "issue_text", "summary")
_TARGET_KEYS = ("target", "file", "filename", "path", "location", "host", "url", "asset", "resource",
                "component", "package", "entity")
_FIX_KEYS = ("recommendation", "remediation", "solution", "fix", "mitigation")
_SEV_KEYS = ("severity", "issue_severity", "risk", "risk_level", "level")


def _get(d: Dict, keys) -> Any:
    low = {str(k).lower(): v for k, v in d.items()}
    for k in keys:
        v = low.get(k)
        if v not in (None, "", [], {}):
            return v
    return None


def _is_finding(d) -> bool:
    return (isinstance(d, dict) and _sev(_get(d, _SEV_KEYS)) is not None
            and (_get(d, _TITLE_KEYS) is not None or _get(d, _RULE_KEYS) is not None))


def _finding_lists(data) -> List[List[Dict]]:
    """Lists of finding-shaped objects at the top level or one or two levels down."""
    found = []

    def consider(v):
        if isinstance(v, list) and v and sum(_is_finding(x) for x in v) >= max(1, int(0.6 * len(v))):
            found.append([x for x in v if _is_finding(x)])

    consider(data)
    if isinstance(data, dict):
        for v in data.values():
            consider(v)
            if isinstance(v, dict):
                for w in v.values():
                    consider(w)
    return found


class CodeScanParser(BaseParser):
    def can_parse(self, filename: str, content: str) -> bool:
        if not content or is_image_file(filename):
            return False
        return bool(self._kind(_load(content)))

    @staticmethod
    def _kind(data) -> str:
        if isinstance(data, dict):
            if str(data.get("version", "")).startswith("2.") and isinstance(data.get("runs"), list):
                return "sarif"
            if isinstance(data.get("matches"), list) and isinstance(data.get("descriptor"), dict):
                return "grype"
            if data.get("auditReportVersion") and isinstance(data.get("vulnerabilities"), dict):
                return "npm2"
            if isinstance(data.get("advisories"), dict) and isinstance(data.get("metadata"), dict):
                return "npm1"
            res = data.get("results")
            if isinstance(res, list) and res and all(isinstance(r, dict) and "issue_severity" in r for r in res):
                return "bandit"
        if isinstance(data, list) and data and all(
                isinstance(r, dict) and "RuleID" in r and "File" in r for r in data):
            return "gitleaks"
        if _finding_lists(data):
            return "generic"
        return ""

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], Any]:
        data = _load(content)
        kind = self._kind(data)
        findings = {
            "sarif": self._sarif, "grype": self._grype, "npm2": self._npm2, "npm1": self._npm1,
            "bandit": self._bandit, "gitleaks": self._gitleaks, "generic": self._generic,
        }.get(kind, lambda _d: [])(data)
        seen, out = set(), []
        for f in findings:
            key = (f.title, f.target, tuple(f.cve_list))
            if key not in seen:
                seen.add(key)
                out.append(f)
        info = [f for f in out if f.severity == "INFO"]
        for f in info:
            f.remediation_actionable = f.remediation_actionable or f.remediation
        return [f for f in out if f.severity != "INFO"], info

    # ── SARIF ────────────────────────────────────────────────────────────────
    @staticmethod
    def _sarif(data) -> List[Finding]:
        out = []
        for run in data.get("runs") or []:
            driver = ((run.get("tool") or {}).get("driver") or {})
            tool = str(driver.get("name") or "SARIF scanner")
            rules = {}
            for r in list(driver.get("rules") or []) + [
                    r for ext in ((run.get("tool") or {}).get("extensions") or []) for r in (ext.get("rules") or [])]:
                if isinstance(r, dict) and r.get("id"):
                    rules[r["id"]] = r
            for res in run.get("results") or []:
                rid = str(res.get("ruleId") or (res.get("rule") or {}).get("id") or "")
                rule = rules.get(rid, {})
                props = rule.get("properties") or {}
                msg = str((res.get("message") or {}).get("text") or "")
                short = str((rule.get("shortDescription") or {}).get("text") or "")
                full = str((rule.get("fullDescription") or {}).get("text") or "")
                helptext = str((rule.get("help") or {}).get("text") or "")
                sev = (_band(props.get("security-severity")) or
                       _sev(res.get("level") or (rule.get("defaultConfiguration") or {}).get("level")) or "MEDIUM")
                loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
                uri = str((loc.get("artifactLocation") or {}).get("uri") or "")
                line = (loc.get("region") or {}).get("startLine")
                target = f"{uri}:{line}" if uri and line else (uri or "Source code")
                title = short or (msg.split(". ")[0][:120] if msg else rid)
                score = props.get("security-severity")
                try:
                    score = float(score) if score not in (None, "") else None
                except (TypeError, ValueError):
                    score = None
                out.append(Finding(
                    title=title,
                    severity=sev,
                    severity_score=score,
                    cve_list=_cves(rid, msg) + _cwes(" ".join(map(str, props.get("tags") or [])), props.get("cwe")),
                    target=target,
                    description="\n\n".join(p for p in (msg, full if full != msg else "") if p) or title,
                    remediation=helptext or f"Fix the code at {target} as the rule '{rid}' describes.",
                    evidence=f"rule: {rid}\nlocation: {target}\nlevel: {res.get('level') or '-'}",
                    plugin_id=rid,
                    source_tool=tool,
                ))
        return out

    # ── Grype ────────────────────────────────────────────────────────────────
    @staticmethod
    def _grype(data) -> List[Finding]:
        from .trivy_parser import _package_steps, _PACKAGE_CVE_CATEGORY
        src = (data.get("source") or {}).get("target")
        target = (src.get("userInput") if isinstance(src, dict) else src) or "Scanned artifact"
        out = []
        for m in data.get("matches") or []:
            v = m.get("vulnerability") or {}
            art = m.get("artifact") or {}
            vid = str(v.get("id") or "")
            pkg, ver = str(art.get("name") or ""), str(art.get("version") or "")
            fixed = ", ".join((v.get("fix") or {}).get("versions") or [])
            cves = _cves(vid, " ".join(str(r.get("id")) for r in m.get("relatedVulnerabilities") or []))
            score, vector = None, None
            for c in v.get("cvss") or []:
                score = (c.get("metrics") or {}).get("baseScore")
                vector = c.get("vector")
                break
            desc = str(v.get("description") or "")
            out.append(Finding(
                title=f"{vid} in {pkg} {ver}" + (f": {desc[:80]}" if desc else ""),
                severity=_sev(v.get("severity")) or "INFO",
                severity_score=score, cvss_vector=vector,
                cve_list=cves or ([vid] if vid.upper().startswith("CVE-") else []),
                target=str(target),
                description=desc or vid,
                remediation=(f"Update {pkg} from {ver} to fixed version {fixed}." if fixed else
                             f"No fixed version available yet for {pkg} {ver}; monitor the advisory for {vid}."),
                remediation_actionable=_package_steps(pkg, ver, fixed, vid),
                category=_PACKAGE_CVE_CATEGORY,
                evidence=f"Package: {pkg} ({art.get('type', '')}) | Installed: {ver} | Fixed: {fixed or 'N/A'}",
                plugin_id=vid,
                source_tool="Grype",
            ))
        return out

    # ── npm audit ────────────────────────────────────────────────────────────
    @staticmethod
    def _npm_finding(title, sev, pkg, rng, cwes, cves, score, vector, url, fix_note) -> Finding:
        return Finding(
            title=f"{title} ({pkg})",
            severity=_sev(sev) or "INFO",
            severity_score=score, cvss_vector=vector or None,
            cve_list=cves + cwes,
            target=f"npm package {pkg} {rng}".strip(),
            description=f"npm audit: {title}. Affected versions of {pkg}: {rng or 'see advisory'}." + (f" {url}" if url else ""),
            remediation=f"Upgrade {pkg} to a version outside {rng}." if rng else f"Upgrade {pkg} to a patched version.",
            remediation_actionable=(f"1. Run 'npm audit fix' (or upgrade {pkg} directly) and commit the lock file. "
                                    f"2. {fix_note} 3. Re-run 'npm audit' and confirm the advisory is gone."),
            category="Vulnerable Components",
            evidence=f"package: {pkg} | range: {rng}" + (f" | advisory: {url}" if url else ""),
            plugin_id=url or title,
            source_tool="npm audit",
        )

    def _npm2(self, data) -> List[Finding]:
        out = []
        for name, entry in (data.get("vulnerabilities") or {}).items():
            fix = entry.get("fixAvailable")
            fix_note = ("A fix is available." if fix is True else
                        (f"Fix by upgrading {fix.get('name')} to {fix.get('version')}." if isinstance(fix, dict)
                         else "No automatic fix is available; replace or patch the dependency."))
            for via in entry.get("via") or []:
                if not isinstance(via, dict):
                    continue            # a transitive pointer; the advisory is on the package it names
                cvss = via.get("cvss") or {}
                out.append(self._npm_finding(
                    str(via.get("title") or "Vulnerable dependency"), via.get("severity") or entry.get("severity"),
                    str(via.get("name") or name), str(via.get("range") or entry.get("range") or ""),
                    _cwes(" ".join(map(str, via.get("cwe") or []))), _cves(via.get("url"), via.get("title")),
                    cvss.get("score") or None, cvss.get("vectorString"), via.get("url"), fix_note))
        return out

    def _npm1(self, data) -> List[Finding]:
        return [self._npm_finding(
            str(a.get("title") or "Vulnerable dependency"), a.get("severity"), str(a.get("module_name") or ""),
            str(a.get("vulnerable_versions") or ""), _cwes(a.get("cwe")), _cves(" ".join(a.get("cves") or [])),
            None, None, a.get("url"), str(a.get("recommendation") or ""))
            for a in (data.get("advisories") or {}).values() if isinstance(a, dict)]

    # ── Bandit ───────────────────────────────────────────────────────────────
    @staticmethod
    def _bandit(data) -> List[Finding]:
        out = []
        for r in data.get("results") or []:
            target = f"{r.get('filename')}:{r.get('line_number')}"
            cwe = (r.get("issue_cwe") or {}).get("id")
            out.append(Finding(
                title=f"{r.get('test_name')} ({r.get('test_id')})",
                severity=_sev(r.get("issue_severity")) or "INFO",
                confidence={"HIGH": "Certain", "MEDIUM": "Firm", "LOW": "Tentative"}.get(
                    str(r.get("issue_confidence") or "").upper(), "Firm"),
                cve_list=[f"CWE-{cwe}"] if cwe else [],
                target=target,
                description=str(r.get("issue_text") or ""),
                remediation=f"Fix the code at {target}: {r.get('issue_text')}" + (
                    f" See {r.get('more_info')}." if r.get("more_info") else ""),
                evidence=full_poc(r.get("code")),
                plugin_id=str(r.get("test_id") or ""),
                source_tool="Bandit",
            ))
        return out

    # ── gitleaks ─────────────────────────────────────────────────────────────
    @staticmethod
    def _gitleaks(data) -> List[Finding]:
        out = []
        for r in data:
            secret = str(r.get("Secret") or "")
            masked = (secret[:4] + "*" * max(4, len(secret) - 8) + secret[-4:]) if len(secret) > 8 else "****"
            target = f"{r.get('File')}:{r.get('StartLine')}"
            out.append(Finding(
                title=f"Secret committed to source: {r.get('Description') or r.get('RuleID')}",
                severity="HIGH",
                target=target,
                description=(f"gitleaks found a {r.get('Description') or r.get('RuleID')} in {target}"
                             + (f" (commit {str(r.get('Commit'))[:12]})" if r.get("Commit") else "")
                             + ". gitleaks assigns no severity; a committed credential is rated HIGH here "
                               "for the auditor to confirm."),
                remediation="Revoke and rotate the credential, remove it from the repository history, and load it from a secret store.",
                remediation_actionable=("1. Revoke/rotate the credential at its issuer now. 2. Remove it from the code "
                                        "and from git history (git filter-repo / BFG). 3. Load it from an environment "
                                        "variable or secret manager. 4. Re-run gitleaks to confirm."),
                # The secret itself is never stored: this record ends up in the
                # audit ledger and every export.
                evidence=f"rule: {r.get('RuleID')} | file: {target} | secret: {masked}",
                plugin_id=str(r.get("RuleID") or ""),
                source_tool="gitleaks",
                is_pii_exposed=True,
            ))
        return out

    # ── generic ──────────────────────────────────────────────────────────────
    @staticmethod
    def _generic(data) -> List[Finding]:
        tool_top = str(data.get("scanner") or data.get("tool") or "") if isinstance(data, dict) else ""
        out = []
        for lst in _finding_lists(data):
            for d in lst:
                rule = _get(d, _RULE_KEYS)
                title = _get(d, _TITLE_KEYS)
                category = d.get("category") if isinstance(d.get("category"), str) else ""
                target = _get(d, _TARGET_KEYS)
                line = d.get("line")
                target = str(target) + (f":{line}" if line not in (None, "", 0, "0") and ":" not in str(target) else "") \
                    if target is not None else "Not recorded"
                if not title:
                    title = (f"{category}: " if category else "") + str(rule) + (
                        f" ({target})" if target != "Not recorded" else "")
                desc = str(_get(d, _DESC_KEYS) or title)
                fix = _get(d, _FIX_KEYS)
                text_blob = " ".join(str(v) for v in d.values() if isinstance(v, (str, int)))
                cves = _cves(rule, title, text_blob)
                tool = str(d.get("tool") or d.get("scanner") or tool_top or "JSON findings report")
                out.append(Finding(
                    title=str(title)[:200],
                    severity=_sev(_get(d, _SEV_KEYS)),
                    cve_list=cves + _cwes(d.get("cwe"), rule),
                    target=target,
                    description=desc,
                    remediation=str(fix) if fix else "Remediate as the scanner's finding describes.",
                    category="Vulnerable Components" if (cves and "depend" in (category + tool).lower()) else "",
                    evidence=full_poc("\n".join(f"{k}: {v}" for k, v in d.items()
                                                if isinstance(v, (str, int, float)) and str(v).strip())),
                    plugin_id=str(rule or ""),
                    source_tool=tool,
                ))
        return out
