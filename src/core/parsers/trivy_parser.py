# -*- coding: utf-8 -*-
import json
from typing import List, Tuple
from .base_parser import BaseParser, is_image_file
from .finding_schema import Finding
from .control_mapper import map_findings_list


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
        # Only check .json files to avoid false-positives from CSV/XML formats
        # that might contain the word 'vulnerabilities' as plain prose.
        if not filename.lower().endswith(".json"):
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
