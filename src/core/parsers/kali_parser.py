# -*- coding: utf-8 -*-
"""
Kali Linux tool output parser.

Covers the console/report output of the tools a Kali-based engagement actually
produces alongside nmap: nikto, sqlmap, gobuster/dirb/ffuf, hydra and wpscan.

Why this exists
---------------
Before this parser the pipeline recognised exactly five formats -- Nessus, Nmap,
Burp, Qualys, Trivy. Everything else was claimed by nobody and returned an empty
list. Verified by execution against realistic output from all five tools above:

    nikto      0 findings   (outdated Apache, directory indexing, missing headers)
    sqlmap     0 findings   (confirmed boolean-based blind SQL injection)
    gobuster   0 findings   (/.git and config.php.bak exposed)
    hydra      0 findings   (valid SSH credentials recovered: admin/admin123)
    wpscan     0 findings   (WordPress 5.8.1, 22 vulns, CVE-2021-39200)

An empty result is indistinguishable from a clean scan in the UI. Uploading proof
of a working SQL injection, or a cracked SSH login, and being told there is
nothing to report is the worst failure mode an audit tool has -- worse than a
crash, because nobody investigates a pass.

Detection is by content signature only, never filename, matching the convention
the other parsers follow (a screenshot named sqlmap.png must reach OCR, not this).
"""
import re
from typing import List, Tuple, Any

from .base_parser import BaseParser, is_image_file
from .finding_schema import Finding


# ── Signatures: banner/structure unique to each tool ────────────────────────
_SIGNATURES = {
    "nikto":    (re.compile(r'-\s*Nikto v[\d.]|nikto\.pl|OSVDB-\d+', re.IGNORECASE),),
    "sqlmap":   (re.compile(r'sqlmap identified the following injection point|\{[\d.]+#stable\}|starting @ .*sqlmap', re.IGNORECASE),
                 re.compile(r'\[INFO\]\s+(?:testing|the back-end DBMS)', re.IGNORECASE)),
    "gobuster": (re.compile(r'Gobuster v[\d.]|=+\s*\nGobuster', re.IGNORECASE),
                 re.compile(r'^/\S+\s+\(Status:\s*\d{3}\)', re.MULTILINE)),
    "hydra":    (re.compile(r'Hydra v[\d.]|hydra \(https?://', re.IGNORECASE),
                 re.compile(r'^\[\d+\]\[\w+\]\s+host:', re.MULTILINE | re.IGNORECASE)),
    "wpscan":   (re.compile(r'WPScan|wpscan\.com|WordPress version [\d.]+ identified', re.IGNORECASE),),
}

# HTTP statuses gobuster/dirb report that represent a real reachable resource.
_INTERESTING_STATUS = {"200", "201", "204", "301", "302", "307", "401", "403", "500"}

# Paths whose exposure is a finding in its own right, regardless of status.
_SENSITIVE_PATH_RE = re.compile(
    r'\.git|\.svn|\.env|\.bak|\.old|\.sql|\.zip|\.tar|backup|dump|config|'
    r'wp-config|id_rsa|\.ssh|admin|phpmyadmin|\.htpasswd|'
    r'server-status|server-info|phpinfo|\.ds_store|web\.config|\.htaccess',
    re.IGNORECASE,
)

# Reference and vendor sites that tool output names in its banner or in "See:"
# links. The target used to be the first URL in the output, which for sqlmap is
# its own banner -- every sqlmap finding was filed against https://sqlmap.org.
_NOT_A_TARGET_RE = re.compile(
    r'https?://(?:[\w.-]*\.)?(?:sqlmap\.org|nmap\.org|github\.com|wpscan\.com|'
    r'cve\.mitre\.org|nvd\.nist\.gov|owasp\.org|mozilla\.org|netsparker\.com|'
    r'wordpress\.org|portswigger\.net|cirt\.net|vntweb\.co\.uk|exploit-db\.com)\b',
    re.IGNORECASE)


def _detect_tool(content: str) -> str:
    """Return the tool name whose signature matches, or "" for none."""
    for tool, patterns in _SIGNATURES.items():
        if any(p.search(content) for p in patterns):
            return tool
    return ""


# Nikto names the problem in its own words; every finding used to get the same
# "review the configuration" sentence, which tells a developer nothing.
_NIKTO_REMEDIATION = (
    ("x-frame-options", "Send 'X-Frame-Options: DENY' (or SAMEORIGIN) and "
                        "'Content-Security-Policy: frame-ancestors 'none'' on every response."),
    ("x-content-type-options", "Send 'X-Content-Type-Options: nosniff' on every response."),
    ("strict-transport-security", "Send 'Strict-Transport-Security: max-age=31536000; "
                                  "includeSubDomains' over HTTPS."),
    ("content-security-policy", "Define a Content-Security-Policy header restricting script, "
                                "frame and object sources."),
    ("x-xss-protection", "Rely on a Content-Security-Policy; set 'X-XSS-Protection: 0' "
                         "rather than the legacy filter."),
    ("outdated", "Upgrade the web server to the current supported release from the vendor."),
    ("out of date", "Upgrade the web server to the current supported release from the vendor."),
    ("default file", "Remove the vendor's default files and sample content from the web root."),
    ("phpmyadmin", "Remove phpMyAdmin from the public site, or restrict it to the admin "
                   "network/VPN behind strong authentication."),
    ("directory indexing", "Disable directory listing (Apache 'Options -Indexes', "
                           "nginx 'autoindex off')."),
    ("index of", "Disable directory listing (Apache 'Options -Indexes', nginx 'autoindex off')."),
    ("trace", "Disable the TRACE/TRACK methods (Apache 'TraceEnable off')."),
    ("allowed http methods", "Allow only the HTTP methods the application uses "
                             "(normally GET, POST, HEAD)."),
    ("etag", "Stop the server deriving ETags from inode numbers (Apache 'FileETag MTime Size')."),
    ("cookie", "Set the Secure, HttpOnly and SameSite attributes on session cookies."),
    ("false positives", "No action required; this is nikto's note that the server answers "
                        "every request, so some of its other results may be false positives."),
)


def _nikto_remediation(low: str) -> str:
    for key, fix in _NIKTO_REMEDIATION:
        if key in low:
            return fix
    return "Review the affected web server configuration and apply the vendor's hardening guidance."


def _target_from(content: str) -> str:
    m = re.search(r'(?:Target IP|Target|Url|\[DATA\] attacking|host):\s*([^\s,\n]+)', content, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # sqlmap names the target in the output directory it logs to, and in some
    # versions in a "testing URL" line.
    m = re.search(r"(?:testing URL|target URL)\s*['\"]?(https?://[^\s'\"]+)", content, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"sqlmap[/\\]output[/\\]([^\s'\"/\\]+)", content, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    for m in re.finditer(r'https?://[^\s,\n\'"]+', content):
        if not _NOT_A_TARGET_RE.match(m.group(0)):
            return m.group(0).strip()
    return "Target Host"


class KaliParser(BaseParser):
    """Parses console output from common Kali Linux assessment tools."""

    def can_parse(self, filename: str, content: str) -> bool:
        if not content or is_image_file(filename):
            return False
        return bool(_detect_tool(content))

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], Any]:
        if not content:
            return [], None
        tool = _detect_tool(content)
        if not tool:
            return [], None

        target = _target_from(content)
        handler = {
            "nikto": self._parse_nikto,
            "sqlmap": self._parse_sqlmap,
            "gobuster": self._parse_gobuster,
            "hydra": self._parse_hydra,
            "wpscan": self._parse_wpscan,
        }[tool]

        findings = handler(content, target)

        # Collapse identical titles -- a directory brute-forcer in particular
        # reports the same class of exposure many times over.
        seen, deduped = set(), []
        for f in findings:
            key = (f.title, f.target)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        # Same split as Nessus: discovered-but-unrated items (a brute-forcer's
        # ordinary pages, an exposed readme) go in the informational list, not
        # the actionable count.
        actionable = [f for f in deduped if f.severity != "INFO"]
        info = [f for f in deduped if f.severity == "INFO"]
        # The mapper's fallback wraps a remediation as "Apply the fix: ... Verify
        # the fix", which reads "Apply the fix: No action required" here.
        for f in info:
            if not f.remediation_actionable:
                f.remediation_actionable = f.remediation
        return actionable, info

    # ── nikto ───────────────────────────────────────────────────────────────
    def _parse_nikto(self, content: str, target: str) -> List[Finding]:
        out = []
        for line in content.splitlines():
            s = line.strip()
            if not s.startswith("+"):
                continue
            body = s.lstrip("+ ").strip()
            if not body or len(body) < 12:
                continue
            # Banner/summary lines carry no finding.
            # "8102 requests: 0 error(s) and 6 item(s) reported on remote host" is
            # nikto's closing tally; it was being published as a seventh finding.
            if re.match(r'^(Target |Start Time|End Time|Server:|SSL Info|\d+ host\(s\) tested'
                        r'|\d+ requests?:|No CGI Directories found|Root page|Scan terminated)',
                        body, re.IGNORECASE) or re.search(r'\bitem\(s\) reported\b', body, re.IGNORECASE):
                continue

            low = body.lower()
            if "outdated" in low or "appears to be out of date" in low:
                sev = "MEDIUM"
            elif "directory indexing" in low or "index of" in low:
                sev = "MEDIUM"
            elif "header is not present" in low or "header is not set" in low or "not defined" in low:
                sev = "LOW"
            elif re.search(r'\bOSVDB-\d+', body):
                sev = "MEDIUM"
            elif "may cause false positives" in low:
                sev = "INFO"                    # nikto's note about its own results
            else:
                sev = "LOW"

            out.append(Finding(
                title=f"Nikto: {body[:110]}",
                severity=sev,
                target=target,
                description=f"Nikto web server scan finding against {target}: {body}",
                remediation=_nikto_remediation(low),
                evidence=s,
                source_tool="Nikto",
            ))
        return out

    # ── sqlmap ──────────────────────────────────────────────────────────────
    def _parse_sqlmap(self, content: str, target: str) -> List[Finding]:
        out = []
        # A confirmed injection point is the headline result.
        for m in re.finditer(
            r'Parameter:\s*(?P<param>[^\s(]+)\s*\((?P<method>[A-Z]+)\)(?P<body>.*?)(?=\nParameter:|\n---|\Z)',
            content, re.DOTALL | re.IGNORECASE,
        ):
            param, method = m.group("param"), m.group("method")
            body = m.group("body")
            types = re.findall(r'Type:\s*([^\n]+)', body)
            titles = re.findall(r'Title:\s*([^\n]+)', body)
            detail = (titles[0].strip() if titles else (types[0].strip() if types else "SQL injection"))
            dbms = re.search(r'back-end DBMS is ([^\n]+)', content, re.IGNORECASE)
            out.append(Finding(
                title=f"SQL Injection confirmed in {method} parameter '{param}' ({detail[:60]})",
                severity="CRITICAL",
                target=target,
                description=(
                    f"sqlmap confirmed an exploitable SQL injection in the {method} parameter "
                    f"'{param}' on {target}. Technique: {', '.join(t.strip() for t in types) or detail}."
                    + (f" Back-end DBMS: {dbms.group(1).strip()}." if dbms else "")
                ),
                remediation=(
                    "Replace dynamic SQL with parameterised queries or prepared statements, validate "
                    "and canonicalise input server-side, and grant the database account least privilege."
                ),
                evidence=body.strip()[:800],
                source_tool="sqlmap",
            ))

        # Heuristic warning with no confirmed point still warrants a finding.
        if not out:
            for m in re.finditer(
                r'(?:heuristic .*? shows that )?(?P<meth>GET|POST)\s+parameter\s+\'(?P<p>[^\']+)\'\s+(?:might be|is)\s+injectable',
                content, re.IGNORECASE,
            ):
                out.append(Finding(
                    title=f"Possible SQL Injection in {m.group('meth')} parameter '{m.group('p')}'",
                    severity="HIGH",
                    target=target,
                    description=(
                        f"sqlmap's heuristic check flagged the {m.group('meth')} parameter "
                        f"'{m.group('p')}' on {target} as potentially injectable. Not confirmed -- verify manually."
                    ),
                    remediation="Verify with a full sqlmap run; if confirmed, move the query to parameterised SQL.",
                    evidence=m.group(0),
                    source_tool="sqlmap",
                    confidence="Tentative",
                ))
        return out

    # ── gobuster / dirb / ffuf ──────────────────────────────────────────────
    def _parse_gobuster(self, content: str, target: str) -> List[Finding]:
        out = []
        for m in re.finditer(
            r'^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d{3})\)(?:\s*\[Size:\s*(?P<size>\d+)\])?',
            content, re.MULTILINE,
        ):
            path, status = m.group("path"), m.group("status")
            if status not in _INTERESTING_STATUS:
                continue
            sensitive = bool(_SENSITIVE_PATH_RE.search(path))
            # A directory brute-forcer lists EVERYTHING that answers, the home
            # page included. Only a sensitive path is a finding; the rest is
            # the site's own content, recorded as discovered but not rated.
            # "/index.php (HTTP 200)" used to be a MEDIUM exposure.
            if sensitive and status in ("200", "201", "204"):
                sev = "HIGH"                    # the content itself is readable
            elif sensitive and status in ("301", "302", "307", "500"):
                sev = "MEDIUM"                  # present and answering
            elif sensitive:
                sev = "LOW"                     # present, access refused
            else:
                sev = "INFO"
            out.append(Finding(
                title=(f"Exposed path discovered: {path} (HTTP {status})" if sensitive
                       else f"Discovered path: {path} (HTTP {status})"),
                severity=sev,
                target=target,
                description=(
                    f"Directory brute-force against {target} found {path} responding with HTTP {status}"
                    + (f" ({m.group('size')} bytes)" if m.group("size") else "")
                    + (". The path name indicates potentially sensitive content." if sensitive else ".")
                ),
                remediation=(
                    "Remove or relocate the resource if it is not intended to be public, disable directory "
                    "listing, and restrict access at the web server or WAF." if sensitive else
                    "No action required if this page is meant to be public; it is recorded as part of "
                    "the discovered attack surface."
                ),
                evidence=m.group(0).strip(),
                source_tool="Gobuster",
            ))
        return out

    # ── hydra ───────────────────────────────────────────────────────────────
    def _parse_hydra(self, content: str, target: str) -> List[Finding]:
        out = []
        for m in re.finditer(
            r'^\[(?P<port>\d+)\]\[(?P<svc>[^\]]+)\]\s+host:\s*(?P<host>\S+)\s+login:\s*(?P<user>\S+)\s+password:\s*(?P<pw>\S+)',
            content, re.MULTILINE | re.IGNORECASE,
        ):
            svc, host, user, port = m.group("svc"), m.group("host"), m.group("user"), m.group("port")
            out.append(Finding(
                title=f"Valid credentials recovered by brute force: {svc} {user}@{host}:{port}",
                severity="CRITICAL",
                target=f"{host}:{port}",
                description=(
                    f"Hydra successfully authenticated to the {svc} service on {host}:{port} using the "
                    f"account '{user}'. The password was recovered by online brute force, meaning it is "
                    f"weak or default and the service has no effective rate limiting or lockout."
                ),
                remediation=(
                    "Rotate the credential immediately, enforce a strong password policy, enable account "
                    "lockout or rate limiting, restrict the service to trusted networks, and prefer key-based "
                    "authentication where the protocol supports it."
                ),
                # The recovered password is deliberately NOT stored -- this record ends up in
                # the audit ledger and exports, and writing a live credential into it would
                # turn the report itself into a disclosure.
                evidence=f"[{port}][{svc}] host: {host}   login: {user}   password: <redacted>",
                source_tool="Hydra",
                is_pii_exposed=True,
            ))
        return out

    # ── wpscan ──────────────────────────────────────────────────────────────
    def _parse_wpscan(self, content: str, target: str) -> List[Finding]:
        out = []

        m = re.search(r'WordPress version ([\d.]+) identified\s*\(([^)]*)\)', content, re.IGNORECASE)
        if m:
            version, note = m.group(1), m.group(2)
            insecure = "insecure" in note.lower() or "outdated" in note.lower()
            out.append(Finding(
                title=f"WordPress {version} identified ({note.strip()[:60]})",
                severity="HIGH" if insecure else "INFO",
                target=target,
                description=f"WPScan identified WordPress {version} on {target}. Scanner note: {note.strip()}.",
                remediation="Upgrade WordPress core to the current supported release.",
                evidence=m.group(0),
                source_tool="WPScan",
            ))

        for tm in re.finditer(r'Title:\s*([^\n]+)', content):
            title = tm.group(1).strip()
            if not title or len(title) < 8:
                continue
            window = content[tm.end():tm.end() + 400]
            # Stop at the next vulnerability so its references are not borrowed.
            nxt = re.search(r'\n\s*\|?\s*\[!\]\s*Title:', window)
            if nxt:
                window = window[:nxt.start()]
            # WPScan 3 prints CVEs as reference links ("cve.mitre.org/...?name=
            # CVE-2020-35489"); only the old "cve: 2020-35489" form was read, so
            # a vulnerability with a published CVE was rated as if it had none.
            cves = sorted({c.upper() for c in re.findall(r'CVE-\d{4}-\d{4,7}', window, re.IGNORECASE)}
                          | {"CVE-" + c for c in re.findall(r'\bcve:\s*(\d{4}-\d{4,7})', window, re.IGNORECASE)})
            fixed = re.search(r'Fixed in:\s*([^\n]+)', window)
            component = re.split(r'\s*(?:<=?|\u2264)\s*\d|\s+-\s+', title, maxsplit=1)[0].strip() or "the affected component"
            dangerous = re.search(r'remote code execution|\brce\b|file upload|sql injection|'
                                  r'authentication bypass|privilege escalation', title, re.IGNORECASE)
            out.append(Finding(
                title=f"WordPress vulnerability: {title[:100]}",
                severity="HIGH" if (cves or dangerous) else "MEDIUM",
                cve_list=cves,
                target=target,
                description=(
                    f"WPScan reported '{title}' against {target}."
                    + (f" Fixed in {fixed.group(1).strip()}." if fixed else "")
                ),
                remediation=(
                    f"Update {component}"
                    + (f" to {fixed.group(1).strip()} or later." if fixed else " to the latest release.")
                ),
                # The flaw is in a third-party theme/plugin, so the developer's
                # step is the vendor update. The keyword templates answered
                # "file upload" with how to write a safe upload handler.
                remediation_actionable=(
                    f"1. Update {component}"
                    + (f" to {fixed.group(1).strip()} or later" if fixed else " to the latest release")
                    + " from the WordPress admin or with 'wp plugin update' / 'wp theme update'. "
                    "2. If no update can be applied, deactivate and remove it. "
                    "3. Re-run WPScan to confirm the vulnerability is no longer reported."
                ),
                evidence=title,
                source_tool="WPScan",
            ))

        # "Interesting Findings" WPScan reports in their own sections, none of
        # which were read: only the core version and "Title:" lines were.
        m = re.search(r'XML-RPC seems to be enabled:\s*(\S+)', content, re.IGNORECASE)
        if m:
            out.append(Finding(
                title="WordPress XML-RPC interface enabled",
                severity="LOW",
                target=target,
                description=(f"WPScan found the XML-RPC endpoint enabled at {m.group(1)}. It allows "
                             f"many password guesses per request and pingback-based reflection."),
                remediation="Disable XML-RPC if unused, or block xmlrpc.php at the web server or WAF.",
                evidence=m.group(0), source_tool="WPScan"))
        m = re.search(r'WordPress readme found:\s*(\S+)', content, re.IGNORECASE)
        if m:
            out.append(Finding(
                title="WordPress readme.html exposed",
                severity="INFO",
                target=target,
                description=f"The WordPress readme is publicly readable at {m.group(1)}, disclosing the version.",
                remediation="Remove readme.html from the web root.",
                evidence=m.group(0), source_tool="WPScan"))
        for bm in re.finditer(r'\[\+\]\s*(?:WordPress theme in use:\s*)?(?P<name>[\w.-]+)\s*\n'
                              r'(?P<body>(?:\s*\|[^\n]*\n)+)', content):
            body = bm.group("body")
            od = re.search(r'The version is out of date, the latest version is\s*([\w.]+)', body)
            if not od:
                continue
            ver = re.search(r'Version:\s*([\w.]+)', body)
            kind = "theme" if "/themes/" in body else ("plugin" if "/plugins/" in body else "component")
            out.append(Finding(
                title=(f"Outdated WordPress {kind}: {bm.group('name')}"
                       + (f" {ver.group(1)}" if ver else "") + f" (latest {od.group(1)})"),
                severity="LOW",
                target=target,
                description=(f"WPScan reports the {kind} '{bm.group('name')}' is out of date; "
                             f"the latest version is {od.group(1)}."),
                remediation=f"Update the {kind} to {od.group(1)} or later, or remove it if unused.",
                evidence=od.group(0), source_tool="WPScan"))
        um = re.search(r'User\(s\) Identified:\s*\n(?P<body>(?:.*\n){0,40})', content)
        if um:
            users = re.findall(r'^\[\+\]\s*([^\s|]+)\s*$', um.group("body"), re.MULTILINE)
            users = [u for u in users if not u.lower().startswith(("finished", "requests", "enumerating"))]
            if users:
                out.append(Finding(
                    title=f"WordPress user enumeration: {', '.join(users[:10])}",
                    severity="LOW",
                    target=target,
                    description=(f"WPScan enumerated {len(users)} account name(s), giving an attacker "
                                 f"half of every login pair: {', '.join(users[:10])}."),
                    remediation=("Block author-archive and REST API user enumeration (/?author=N, "
                                 "/wp-json/wp/v2/users) and enforce strong passwords with lockout."),
                    evidence="User(s) Identified: " + ", ".join(users[:10]), source_tool="WPScan"))
        return out
