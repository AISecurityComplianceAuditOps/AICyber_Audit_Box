# -*- coding: utf-8 -*-
"""Code / dependency scanner exports and generic findings files, with the answer."""
import json

C = {}

# A CI security pipeline's own report: a "findings" list beside counters.
C["pipeline_json"] = ("devsecops_report.json", json.dumps({
    "report": {"repo": "shop-api", "cve_high": 2, "cve_low": 1, "gate_passed": False},
    "trend": [{"run_id": "a1", "cve_high": 2}],
    "findings": [
        {"tool": "dependency-check", "category": "Vulnerable Dependency", "severity": "HIGH",
         "file": "requirements.txt:PyJWT/2.13.0", "line": 0, "rule": "CVE-2025-45770",
         "description": "jwt contains weak encryption.", "recommendation": "Upgrade pyjwt."},
        {"tool": "dependency-check", "category": "Vulnerable Dependency", "severity": "MEDIUM",
         "file": "requirements.txt:reportlab/5.0.0", "line": 0, "rule": "CVE-2020-28463",
         "description": "reportlab SSRF via img tags.", "recommendation": "Upgrade reportlab."}]}),
    dict(min=2, max=2, mention=["CVE-2025-45770", "CVE-2020-28463", "PyJWT"],
         sev={"CVE-2025-45770": "HIGH", "CVE-2020-28463": "MEDIUM"}))

C["sarif_semgrep"] = ("semgrep.sarif", json.dumps({
    "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{"tool": {"driver": {"name": "Semgrep OSS", "rules": [
        {"id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
         "shortDescription": {"text": "Detected possible formatted SQL query"},
         "fullDescription": {"text": "Detected possible formatted SQL query. Use parameterized queries instead."},
         "help": {"text": "Use parameterized queries."},
         "properties": {"precision": "very-high", "tags": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command", "security"],
                        "security-severity": "8.0"}},
        {"id": "python.flask.security.audit.debug-enabled.debug-enabled",
         "shortDescription": {"text": "Flask debug mode enabled"},
         "properties": {"tags": ["CWE-489: Active Debug Code"]}}]}},
        "results": [
            {"ruleId": "python.lang.security.audit.formatted-sql-query.formatted-sql-query", "level": "error",
             "message": {"text": "Detected possible formatted SQL query. Use parameterized queries instead."},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/db.py"}, "region": {"startLine": 42}}}]},
            {"ruleId": "python.flask.security.audit.debug-enabled.debug-enabled", "level": "warning",
             "message": {"text": "Detected Flask app with debug=True."},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/main.py"}, "region": {"startLine": 7}}}]}]}]}),
    dict(min=2, max=2, mention=["app/db.py", "app/main.py"], sev={"formatted SQL": "HIGH", "debug": "MEDIUM"}))

C["grype_json"] = ("grype.json", json.dumps({"matches": [
    {"vulnerability": {"id": "CVE-2023-0286", "severity": "High", "description": "X.400 address type confusion",
                       "fix": {"versions": ["1.1.1n-0+deb11u4"], "state": "fixed"},
                       "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H", "metrics": {"baseScore": 7.4}}]},
     "artifact": {"name": "openssl", "version": "1.1.1n-0+deb11u3", "type": "deb"}},
    {"vulnerability": {"id": "GHSA-hrpp-h998-j3pp", "severity": "Medium", "description": "qs prototype poisoning",
                       "fix": {"versions": ["6.10.3"], "state": "fixed"}},
     "relatedVulnerabilities": [{"id": "CVE-2022-24999"}],
     "artifact": {"name": "qs", "version": "6.5.2", "type": "npm"}}],
    "source": {"type": "image", "target": {"userInput": "shop:1.0"}},
    "descriptor": {"name": "grype", "version": "0.74.0"}}),
    dict(min=2, max=2, mention=["CVE-2023-0286", "openssl", "qs"], sev={"openssl": "HIGH", "qs": "MEDIUM"}))

C["npm_audit"] = ("npm-audit.json", json.dumps({"auditReportVersion": 2, "vulnerabilities": {
    "qs": {"name": "qs", "severity": "high", "isDirect": False, "via": [
        {"source": 1090134, "name": "qs", "dependency": "qs", "title": "qs vulnerable to Prototype Pollution",
         "url": "https://github.com/advisories/GHSA-hrpp-h998-j3pp", "severity": "high", "cwe": ["CWE-1321"],
         "cvss": {"score": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}, "range": "<6.10.3"}],
        "effects": ["express"], "range": "<6.10.3", "nodes": ["node_modules/qs"], "fixAvailable": True},
    "express": {"name": "express", "severity": "high", "isDirect": True, "via": ["qs"], "effects": [], "range": "<=4.17.2",
                "nodes": ["node_modules/express"], "fixAvailable": True}},
    "metadata": {"vulnerabilities": {"high": 2, "total": 2}}}),
    dict(min=1, mention=["Prototype Pollution", "qs"], sev={"Prototype Pollution": "HIGH"}))

C["gitleaks_json"] = ("gitleaks.json", json.dumps([
    {"Description": "AWS Access Key", "StartLine": 12, "EndLine": 12, "Match": "AKIAIOSFODNN7EXAMPLE",
     "Secret": "AKIAIOSFODNN7EXAMPLE", "File": "config/settings.py", "Commit": "a1b2c3", "RuleID": "aws-access-token",
     "Author": "dev", "Date": "2025-06-01T10:00:00Z"}]),
    dict(min=1, max=1, mention=["AWS Access Key", "config/settings.py"], none=["AKIAIOSFODNN7EXAMPLE"]))

C["bandit_json"] = ("bandit.json", json.dumps({"results": [
    {"code": "subprocess.call(cmd, shell=True)", "filename": "app/run.py", "issue_confidence": "HIGH",
     "issue_severity": "HIGH", "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
     "issue_text": "subprocess call with shell=True identified, security issue.", "line_number": 15,
     "test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true"}],
    "metrics": {"_totals": {"SEVERITY.HIGH": 1}}}),
    dict(min=1, max=1, mention=["shell=True", "app/run.py"], sev={"shell": "HIGH"}))

C["generic_csv"] = ("pentest_tracker.csv",
    "Vulnerability,Severity,Host,Description,Recommendation\n"
    "SQL Injection in login form,Critical,https://portal.test/login,The username parameter is injectable.,Use parameterised queries.\n"
    "Missing HSTS header,Low,https://portal.test/,Strict-Transport-Security is not set.,Add the HSTS header.\n",
    dict(min=2, max=2, mention=["SQL Injection in login form", "Missing HSTS header"],
         sev={"SQL Injection": "CRITICAL", "HSTS": "LOW"}))
