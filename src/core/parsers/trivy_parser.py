# -*- coding: utf-8 -*-
import json
import re
from typing import List, Tuple
from .base_parser import BaseParser, is_image_file
from .finding_schema import Finding
from .control_mapper import map_findings_list


# ── Trivy's text output (its default: `trivy image shop:1.0`) ─────────────────
# Vulnerabilities come as a box-drawn table (ASCII "|" and "+" in older
# versions); misconfigurations as "HIGH: <message>" or "AVD-DS-0002 (HIGH):
# <message>" blocks under a "Tests: N (SUCCESSES: .., FAILURES: ..)" line.
_TABLE_HEADER_RE = re.compile(r'[│|]\s*Library\s*[│|]\s*Vulnerability(?: ID)?\s*[│|]\s*Severity\s*[│|]')
_MISCONF_TESTS_RE = re.compile(r'^Tests: \d+ \(SUCCESSES: \d+, FAILURES: \d+', re.MULTILINE)
_MISCONF_RE = re.compile(r'^(?:(?P<id>[A-Z]+-[A-Z]+-\d+|[A-Z]{2,}\d+) \()?(?P<sev>CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)\)?: (?P<msg>.+)$',
                         re.MULTILINE)


# A known CVE in an installed package is OWASP A06 whatever the bug inside it
# is. Left to the shared keyword pass, one image's openssl CVE was filed under
# Cryptographic Failures and its zlib CVE under Security Misconfiguration.
_PACKAGE_CVE_CATEGORY = "Vulnerable Components"


def _package_steps(pkg: str, installed: str, fixed: str, vid: str) -> str:
    if fixed:
        return (f"1. Update {pkg} from {installed} to {fixed} or later (rebuild the image on an updated base, "
                f"or bump the dependency and regenerate the lock file). 2. Redeploy. "
                f"3. Re-run Trivy and confirm {vid} is no longer reported.")
    return (f"1. No fixed release of {pkg} exists yet for {vid}; track the vendor advisory. "
            f"2. Until then, remove the package if unused or mitigate as the advisory describes. "
            f"3. Re-run Trivy after the fix is published.")


def _next_text_line(lines, i):
    """The next non-blank line after lines[i]. A document extractor puts a blank
    line between paragraphs, which separated the target name from its "====="
    underline and lost the target (Trivy output pasted into Word)."""
    for follow in lines[i + 1:i + 3]:
        if follow.strip():
            return follow.strip()
    return ""


def _is_trivy_text(content: str) -> bool:
    return bool(_TABLE_HEADER_RE.search(content) or _MISCONF_TESTS_RE.search(content))


def _cells(line: str) -> List[str]:
    return [c.strip() for c in re.split(r'[│|]', line.strip())[1:-1]]


def _parse_trivy_text(content: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = content.splitlines()
    target, header, rec, library = "", None, None, ""

    def _flush():
        if rec is None:
            return
        vid = rec.get("vulnerability", "")
        pkg = rec.get("library", "")
        inst = rec.get("installed version", "")
        fixed = rec.get("fixed version", "")
        title = re.sub(r'\s+', ' ', " ".join(rec["title_parts"])).strip() or vid
        findings.append(Finding(
            title=title,
            severity=rec.get("severity", "UNKNOWN") or "UNKNOWN",
            cve_list=[vid.upper()] if vid.upper().startswith("CVE-") else [],
            target=target or "Trivy scan target",
            description=title,
            remediation=(f"Update {pkg} from {inst} to fixed version {fixed}." if fixed else
                         f"No fixed version available yet for {pkg} {inst}; monitor vendor advisory for {vid}."),
            evidence=f"Package: {pkg} | Installed: {inst} | Fixed: {fixed or 'N/A'}"
                     + (f" | {rec['url']}" if rec.get("url") else ""),
            plugin_id=vid,
            category=_PACKAGE_CVE_CATEGORY,
            remediation_actionable=_package_steps(pkg, inst, fixed, vid),
            source_tool="Trivy",
        ))

    for i, raw in enumerate(lines):
        line = raw.rstrip()
        nxt = _next_text_line(lines, i)
        # "shop:1.0 (debian 11.6)" underlined with "=====" names the target.
        if line.strip() and nxt and set(nxt) == {"="} and not line.strip().startswith(("│", "|")):
            _flush()
            rec, header, library, target = None, None, "", line.strip()
            continue
        if _TABLE_HEADER_RE.search(line):
            header = [c.lower() for c in _cells(line)]
            continue
        if header is None or not line.strip().startswith(("│", "|")):
            continue
        cells = _cells(line)
        if len(cells) != len(header):
            continue
        row = dict(zip(header, cells))
        vid = row.get("vulnerability") or row.get("vulnerability id") or ""
        if vid:
            _flush()
            # Trivy merges the Library cell over consecutive rows of one package.
            library = row.get("library") or library
            rec = {"vulnerability": vid, "library": library, "severity": row.get("severity", ""),
                   "installed version": row.get("installed version", ""),
                   "fixed version": row.get("fixed version", ""), "title_parts": [], "url": ""}
        if rec is None:
            continue
        t = row.get("title", "")
        if t.startswith("https://"):
            rec["url"] = t
        elif t:
            rec["title_parts"].append(t)
        for col in ("installed version", "fixed version"):
            if not vid and row.get(col):
                rec[col] = (rec[col] + row[col]).strip()
    _flush()

    # Misconfiguration blocks (trivy config / the misconfig scanner).
    if _MISCONF_TESTS_RE.search(content):
        section = ""
        for i, raw in enumerate(lines):
            nxt = _next_text_line(lines, i)
            if raw.strip() and nxt and set(nxt) == {"="}:
                section = raw.strip()
                continue
            m = _MISCONF_RE.match(raw.strip())
            if not m:
                continue
            body, url = [], ""
            for follow in lines[i + 1:i + 15]:
                s = follow.strip()
                if _MISCONF_RE.match(s) or s.startswith("Tests:"):
                    break
                if s.startswith("See http"):
                    url = s[4:].strip()
                elif s and set(s) - set("═─-="):
                    body.append(s)
            findings.append(Finding(
                title=m.group("msg").strip(),
                severity=m.group("sev"),
                target=section or "Trivy scan target",
                description=" ".join(body) or m.group("msg").strip(),
                remediation=m.group("msg").strip(),
                evidence=raw.strip() + (f" | {url}" if url else ""),
                plugin_id=m.group("id") or "",
                source_tool="Trivy",
            ))
    return findings


class TrivyParser(BaseParser):
    """Parses Trivy JSON scan output (container image / filesystem / repo scans) and
    OWASP Dependency-Check JSON output (SCA dependency vulnerability scans).
    Schema references:
      Trivy: https://aquasecurity.github.io/trivy/latest/docs/configuration/reporting/#json
      Dependency-Check: https://jeremylong.github.io/DependencyCheck/general/internals.html
    Handles Trivy's Vulnerabilities (CVE-based) and Misconfigurations (IaC) result types,
    and Dependency-Check's per-dependency vulnerabilities list.

    NOTE: Dependency-Check support is built against the documented/published schema, not
    yet verified against a real Dependency-Check export -- if a real export doesn't parse,
    compare its actual field names against _parse_dependency_check below and adjust.
    """

    def can_parse(self, filename: str, content: str) -> bool:
        """Content-signature based detection — 0% filename keyword dependency.
        Rejects image files immediately, then inspects JSON schema fields
        that are exclusive to Trivy or Dependency-Check scan output.
        """
        if not content:
            return False
        # Guard: reject image files regardless of their filename.
        if is_image_file(filename):
            return False
        # Trivy's default output is a table, not JSON, and was read by nothing.
        if _is_trivy_text(content):
            return True
        # JSON by content, not by extension: a Trivy JSON report saved as .txt
        # (or with no extension) was rejected here. Requiring the document to BE
        # JSON still keeps prose that mentions "vulnerabilities" out.
        if content.lstrip()[:1] not in "[{":
            return False
        # Scans the FULL content, not a fixed-size prefix -- "schemaversion" sits at
        # the JSON root and appears early, but "vulnerabilities"/"misconfigurations"
        # can be nested deep inside a large Results array on a big scan, past any
        # small fixed window (see burp_parser.py/nessus_parser.py for the real-world
        # case that surfaced this class of bug).
        sample = content.lower()
        # Trivy always produces JSON with 'SchemaVersion' + 'Results' at the root.
        # 'Vulnerabilities' / 'Misconfigurations' arrays appear inside each Result.
        if "schemaversion" in sample and ("vulnerabilities" in sample or "misconfigurations" in sample):
            return True
        # OWASP Dependency-Check produces a root-level "dependencies" array, each entry
        # carrying its own lower-case "vulnerabilities" list and a "fileName" field --
        # a distinct JSON shape from Trivy's PascalCase "Results"/"Vulnerabilities"/
        # "PkgName". "reportschema" is Dependency-Check's own top-level version marker
        # (distinct key from Trivy's "schemaversion").
        if '"dependencies"' in sample and ('"filename"' in sample or "reportschema" in sample):
            return True
        return False

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], List[Finding]]:
        if content.lstrip()[:1] not in "[{" and _is_trivy_text(content):
            findings = _parse_trivy_text(content)
            map_findings_list(findings)
            return self._split_by_severity(findings)
        try:
            data = json.loads(content)
        except Exception as e:
            print(f"[TRIVY PARSER ERROR] Failed to parse '{filename}' as JSON: {e}", flush=True)
            return [], []

        # Dependency-Check's root has "dependencies"; Trivy's has "Results". Checking
        # for the absence of Trivy's own key avoids misrouting a Trivy report that
        # happens to mention the word "dependencies" somewhere in free text.
        if isinstance(data, dict) and "dependencies" in data and "Results" not in data:
            return self._parse_dependency_check(filename, data)
        return self._parse_trivy(filename, data)

    @staticmethod
    def _split_by_severity(findings: List[Finding]) -> Tuple[List[Finding], List[Finding]]:
        """Splits into actionable (CRITICAL/HIGH/MEDIUM/LOW) vs informational
        (UNKNOWN/anything else), matching the actionable/info split every other
        parser in this suite (Nessus, Burp) already does -- previously Trivy/
        Dependency-Check returned everything as one undifferentiated "actionable"
        list regardless of severity."""
        actionable, info = [], []
        for f in findings:
            if str(getattr(f, "severity", "")).upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                actionable.append(f)
            else:
                info.append(f)
        return actionable, info

    def _parse_trivy(self, filename: str, data: dict) -> Tuple[List[Finding], List[Finding]]:
        findings: List[Finding] = []

        results = data.get("Results") or []
        if not isinstance(results, list):
            print(f"[TRIVY PARSER WARNING] '{filename}' has no 'Results' array; nothing to extract.", flush=True)
            return [], []

        for result in results:
            target = str(result.get("Target") or data.get("ArtifactName") or filename)

            # ── CVE-based vulnerability findings ──────────────────────────
            for vuln in (result.get("Vulnerabilities") or []):
                vuln_id = str(vuln.get("VulnerabilityID") or "").strip()
                pkg_name = str(vuln.get("PkgName") or "")
                installed_ver = str(vuln.get("InstalledVersion") or "")
                fixed_ver = str(vuln.get("FixedVersion") or "")
                title = str(vuln.get("Title") or vuln_id or f"Vulnerable package: {pkg_name}")
                description = str(vuln.get("Description") or title)
                severity = str(vuln.get("Severity") or "UNKNOWN")

                cve_list = [vuln_id] if vuln_id.upper().startswith("CVE-") else []

                cvss_score = None
                cvss_vector = None
                cvss_data = vuln.get("CVSS") or {}
                for _, source_scores in cvss_data.items():
                    if isinstance(source_scores, dict):
                        if source_scores.get("V3Score") is not None:
                            cvss_score = source_scores.get("V3Score")
                            cvss_vector = source_scores.get("V3Vector")
                            break
                        if source_scores.get("V2Score") is not None:
                            cvss_score = source_scores.get("V2Score")
                            cvss_vector = source_scores.get("V2Vector")

                remediation = (
                    f"Update {pkg_name} from {installed_ver} to fixed version {fixed_ver}."
                    if fixed_ver else
                    f"No fixed version available yet for {pkg_name} {installed_ver}; monitor vendor advisory for {vuln_id}."
                )

                findings.append(Finding(
                    title=title,
                    severity=severity,
                    severity_score=cvss_score,
                    cvss_vector=cvss_vector,
                    cve_list=cve_list,
                    target=target,
                    description=description,
                    remediation=remediation,
                    evidence=f"Package: {pkg_name} | Installed: {installed_ver} | Fixed: {fixed_ver or 'N/A'}",
                    plugin_id=vuln_id,
                    category=_PACKAGE_CVE_CATEGORY,
                    remediation_actionable=_package_steps(pkg_name, installed_ver, fixed_ver, vuln_id),
                    source_tool="Trivy",
                ))

            # ── IaC / config misconfiguration findings (Dockerfile, Terraform, K8s, etc.) ──
            for misconf in (result.get("Misconfigurations") or []):
                misconf_id = str(misconf.get("ID") or "")
                title = str(misconf.get("Title") or misconf_id or "Misconfiguration")
                severity = str(misconf.get("Severity") or "UNKNOWN")
                description = str(misconf.get("Description") or title)
                resolution = str(misconf.get("Resolution") or "Review and remediate per Trivy misconfiguration guidance.")
                message = str(misconf.get("Message") or "")

                findings.append(Finding(
                    title=title,
                    severity=severity,
                    target=target,
                    description=description,
                    remediation=resolution,
                    evidence=message,
                    plugin_id=misconf_id,
                    source_tool="Trivy",
                ))

        map_findings_list(findings)
        actionable, info = self._split_by_severity(findings)
        print(f"[TRIVY PARSER] Extracted {len(findings)} finding(s) from '{filename}' ({len(actionable)} actionable, {len(info)} informational).", flush=True)
        return actionable, info

    def _parse_dependency_check(self, filename: str, data: dict) -> Tuple[List[Finding], List[Finding]]:
        findings: List[Finding] = []

        dependencies = data.get("dependencies") or []
        if not isinstance(dependencies, list):
            print(f"[DEPENDENCY-CHECK PARSER WARNING] '{filename}' has no 'dependencies' array; nothing to extract.", flush=True)
            return [], []

        for dep in dependencies:
            if not isinstance(dep, dict):
                continue
            file_name = str(dep.get("fileName") or dep.get("filePath") or "unknown dependency")
            packages = dep.get("packages") or []
            pkg_id = str(packages[0].get("id")) if packages and isinstance(packages[0], dict) and packages[0].get("id") else file_name

            for vuln in (dep.get("vulnerabilities") or []):
                if not isinstance(vuln, dict):
                    continue
                vuln_name = str(vuln.get("name") or "").strip()
                severity = str(vuln.get("severity") or "UNKNOWN")
                description = str(vuln.get("description") or vuln_name or f"Vulnerable dependency: {file_name}")
                source = str(vuln.get("source") or "")

                cve_list = [vuln_name] if vuln_name.upper().startswith("CVE-") else []

                cvssv3 = vuln.get("cvssv3") or {}
                cvssv2 = vuln.get("cvssv2") or {}
                cvss_score = cvssv3.get("baseScore")
                if cvss_score is None:
                    cvss_score = cvssv2.get("score")
                cvss_vector = cvssv3.get("vectorString") or cvssv2.get("vectorString")

                references = vuln.get("references") or []
                ref_urls = [r.get("url") for r in references if isinstance(r, dict) and r.get("url")]

                remediation = f"Upgrade or patch the vulnerable dependency '{file_name}' to a version that resolves {vuln_name or 'this finding'}."
                if ref_urls:
                    remediation += f" References: {', '.join(ref_urls[:3])}"

                findings.append(Finding(
                    title=f"{vuln_name}: {file_name}" if vuln_name else f"Vulnerable dependency: {file_name}",
                    severity=severity,
                    severity_score=cvss_score,
                    cvss_vector=cvss_vector,
                    cve_list=cve_list,
                    target=file_name,
                    description=description,
                    remediation=remediation,
                    evidence=f"Dependency: {file_name} | Source: {source or 'N/A'} | Package: {pkg_id}",
                    plugin_id=vuln_name,
                    source_tool="OWASP Dependency-Check",
                ))

        map_findings_list(findings)
        actionable, info = self._split_by_severity(findings)
        print(f"[DEPENDENCY-CHECK PARSER] Extracted {len(findings)} finding(s) from '{filename}' ({len(actionable)} actionable, {len(info)} informational).", flush=True)
        return actionable, info
