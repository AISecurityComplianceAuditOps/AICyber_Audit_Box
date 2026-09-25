# -*- coding: utf-8 -*-
"""
Kali Linux tool output parser.

Covers what a Kali-based engagement produces alongside nmap, in every output
format those tools write:

    nikto        console, -Format csv, -Format xml, -Format json
    sqlmap       console, output/<host>/log, results-*.csv
    gobuster     console, -o file, v2 and v3
    dirb         console
    ffuf         console, -of json
    feroxbuster  console
    hydra        console, -o file, -b json
    medusa       console
    wpscan       console, -f json
    enum4linux   enum4linux and enum4linux-ng console
    masscan      console, -oL list

Why this exists
---------------
Before this parser the pipeline recognised exactly five formats -- Nessus, Nmap,
Burp, Qualys, Trivy. Everything else was claimed by nobody and returned an empty
list. An empty result is indistinguishable from a clean scan in the UI. Uploading
proof of a working SQL injection, or a cracked SSH login, and being told there is
nothing to report is the worst failure mode an audit tool has -- worse than a
crash, because nobody investigates a pass.

The first version read only each tool's console output. The same scan saved in
the tool's own structured format -- nikto's CSV/XML/JSON, ffuf's JSON, hydra's
JSON, wpscan's JSON -- still produced nothing (wpscan JSON produced two of its
seven findings, filed against https://automattic.com from the banner), and
dirb, ffuf, feroxbuster, medusa, enum4linux and masscan were not read at all.

Each tool has ONE builder per finding type, shared by all of its formats, so
the same scan gives the same findings whichever file the auditor uploads.

Detection is by content signature only, never filename, matching the convention
the other parsers follow (a screenshot named sqlmap.png must reach OCR, not this).
"""
import csv
import io
import json
import re
from typing import Any, List, Optional, Tuple
from urllib.parse import urlsplit

from .base_parser import BaseParser, is_image_file
from .finding_schema import Finding, full_poc


# ── Signatures: banner/structure unique to each tool ────────────────────────
# Console formats. Structured formats (JSON, XML, CSV) are recognised by their
# schema in _detect_structured() before these are tried: the wpscan and nikto
# patterns below also match inside their own JSON/CSV files.
_SIGNATURES = {
    "nikto":    (re.compile(r'-\s*Nikto v[\d.]|nikto\.pl|OSVDB-\d+', re.IGNORECASE),),
    "sqlmap":   (re.compile(r'sqlmap identified the following injection point|\{[\d.]+#stable\}|starting @ .*sqlmap', re.IGNORECASE),
                 re.compile(r'\[INFO\]\s+(?:testing|the back-end DBMS)', re.IGNORECASE)),
    "gobuster": (re.compile(r'Gobuster v[\d.]|=+\s*\nGobuster', re.IGNORECASE),
                 re.compile(r'^/\S+\s+\(Status:\s*\d{3}\)', re.MULTILINE)),
    "hydra":    (re.compile(r'Hydra v[\d.]|hydra \(https?://', re.IGNORECASE),
                 re.compile(r'^\[\d+\]\[\w+\]\s+host:', re.MULTILINE | re.IGNORECASE)),
    "wpscan":   (re.compile(r'WPScan|wpscan\.com|WordPress version [\d.]+ identified', re.IGNORECASE),),
    "medusa":   (re.compile(r'Medusa v[\d.]+ \[http://www\.foofus\.net\]', re.IGNORECASE),
                 re.compile(r'^ACCOUNT FOUND:\s*\[\w+\]\s*Host:', re.MULTILINE)),
    "dirb":     (re.compile(r'^DIRB v[\d.]', re.MULTILINE),
                 re.compile(r'^\+ https?://\S+ \(CODE:\d{3}\|SIZE:\d+\)', re.MULTILINE)),
    "ffuf":     (re.compile(r'^\S+\s+\[Status: \d{3}, Size: \d+, Words: \d+, Lines: \d+', re.MULTILINE),),
    "feroxbuster": (re.compile(r'^\d{3}\s+[A-Z]+\s+\d+l\s+\d+w\s+\d+c\s+https?://', re.MULTILINE),),
    "enum4linux": (re.compile(r'Starting enum4linux(?:-ng)? v[\d.]', re.IGNORECASE),
                   re.compile(r'ENUM4LINUX - next generation', re.IGNORECASE)),
    "masscan":  (re.compile(r'Starting masscan [\d.]+', re.IGNORECASE),
                 re.compile(r'^#masscan\b', re.MULTILINE)),
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
    r'wordpress\.org|portswigger\.net|cirt\.net|vntweb\.co\.uk|exploit-db\.com|'
    r'automattic\.com|foofus\.net|bit\.ly|portcullis\.co\.uk)\b',
    re.IGNORECASE)

# Services that are a finding merely by being open (same list as nmap).
_RISKY_PORTS = {
    "23": ("HIGH", "Cleartext Remote Login Service (Telnet)"),
    "513": ("HIGH", "Cleartext Remote Login Service (rlogin)"),
    "514": ("HIGH", "Cleartext Remote Shell Service (rsh)"),
    "512": ("HIGH", "Cleartext Remote Execution Service (rexec)"),
}

def _cleartext_login_steps(port: str, host: str) -> str:
    """Developer steps for Telnet / r-services. The shared "cleartext" template
    answers with FTPS/SFTP/HTTPS, none of which replaces a remote shell."""
    return (f"1. Confirm what listens on {host}:{port} (e.g. 'ss -tlnp' / 'netstat -ano'). "
            f"2. Stop and disable it (systemctl disable --now telnet.socket / inetd entry for "
            f"telnet, rlogin, rsh, rexec). 3. Use SSH for remote administration. "
            f"4. If it cannot be removed, allow it only from a management network. "
            f"5. Re-scan and confirm {port}/tcp is closed.")


# sqlmap's technique letters (--technique, and the results CSV column).
_SQLMAP_TECHNIQUES = {
    "B": "boolean-based blind", "E": "error-based", "U": "UNION query",
    "S": "stacked queries", "T": "time-based blind", "Q": "inline query",
}


def _load_json(content: str):
    s = (content or "").strip()
    if not s or s[0] not in "[{":
        return None
    try:
        return json.loads(s)
    except ValueError:
        return None


def _detect_structured(content: str) -> str:
    """A tool's structured export, recognised by its schema."""
    if "<niktoscan" in content[:4000].lower():
        return "nikto_xml"
    head = content.lstrip()[:200]
    # Quotes optional: a CSV re-saved from Excel loses them.
    if re.match(r'"?Nikto - v\d', head) or re.match(r'"?host ip"?,"?host name"?,"?port"?', head.lower()):
        return "nikto_csv"
    if re.match(r'\s*Target URL,Place,Parameter,Technique\(s\)', content):
        return "sqlmap_csv"
    data = _load_json(content)
    if isinstance(data, dict):
        banner = data.get("banner") if isinstance(data.get("banner"), dict) else {}
        if "interesting_findings" in data or "WPScan" in str(banner.get("description", "")):
            return "wpscan_json"
        gen = data.get("generator") if isinstance(data.get("generator"), dict) else {}
        if str(gen.get("software", "")).lower() == "hydra":
            return "hydra_json"
        res = data.get("results")
        if "commandline" in data and isinstance(res, list) and all(
                isinstance(r, dict) and "status" in r and "url" in r for r in res):
            return "ffuf_json"
    hosts = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    if hosts and all(isinstance(h, dict) for h in hosts) and any(
            isinstance(h.get("vulnerabilities"), list) and h["vulnerabilities"]
            and all(isinstance(v, dict) and "msg" in v for v in h["vulnerabilities"])
            for h in hosts):
        return "nikto_json"
    return ""


def _detect_tool(content: str) -> str:
    """Return the tool (and format) whose signature matches, or "" for none."""
    structured = _detect_structured(content)
    if structured:
        return structured
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


def _host_label(hostname: str, ip: str, port: str = "") -> str:
    hostname, ip, port = (hostname or "").strip(), (ip or "").strip(), str(port or "").strip()
    label = (f"{hostname} ({ip})" if hostname and ip and hostname != ip
             else (hostname or ip or "Target Host"))
    return f"{label}:{port}" if port else label


def _site(url: str) -> Tuple[str, str]:
    """(scheme://host[:port], path) of a URL."""
    parts = urlsplit(url)
    if not parts.netloc:
        return url, ""
    return f"{parts.scheme}://{parts.netloc}", parts.path or "/"


# ── One builder per finding type, shared by every format of a tool ──────────

def _nikto_finding(body: str, target: str, evidence: str) -> Optional[Finding]:
    body = (body or "").strip()
    if not body or len(body) < 12:
        return None
    # Banner/summary lines carry no finding.
    # "8102 requests: 0 error(s) and 6 item(s) reported on remote host" is
    # nikto's closing tally; it was being published as a seventh finding.
    if re.match(r'^(Target |Start Time|End Time|Server:|SSL Info|\d+ host\(s\) tested'
                r'|\d+ requests?:|No CGI Directories found|Root page|Scan terminated)',
                body, re.IGNORECASE) or re.search(r'\bitem\(s\) reported\b', body, re.IGNORECASE):
        return None
    low = body.lower()
    # Severity from what nikto says, not from whether the line carries an
    # OSVDB reference: nikto 2.1 prefixes most lines with one and 2.5 prints
    # none, so the same default file came out MEDIUM or LOW by nikto version.
    if "outdated" in low or "appears to be out of date" in low:
        sev = "MEDIUM"
    elif "directory indexing" in low or "index of" in low:
        sev = "MEDIUM"
    elif "may cause false positives" in low:
        sev = "INFO"                    # nikto's note about its own results
    else:
        sev = "LOW"
    return Finding(
        title=f"Nikto: {body[:110]}",
        severity=sev,
        target=target,
        description=f"Nikto web server scan finding against {target}: {body}",
        remediation=_nikto_remediation(low),
        evidence=evidence,
        source_tool="Nikto",
    )


def _nikto_body(uri: str, msg: str) -> str:
    """The console form "<uri>: <message>" from a structured record."""
    uri, msg = (uri or "").strip(), (msg or "").strip()
    if not uri or msg.startswith(uri + ":") or msg.startswith(uri + " "):
        return msg
    return f"{uri}: {msg}"


def _sqli_finding(param: str, method: str, detail: str, techniques: List[str], target: str,
                  dbms: str = "", evidence: str = "") -> Finding:
    return Finding(
        title=f"SQL Injection confirmed in {method} parameter '{param}' ({detail[:60]})",
        severity="CRITICAL",
        target=target,
        description=(
            f"sqlmap confirmed an exploitable SQL injection in the {method} parameter "
            f"'{param}' on {target}. Technique: {', '.join(techniques) or detail}."
            + (f" Back-end DBMS: {dbms}." if dbms else "")
        ),
        remediation=(
            "Replace dynamic SQL with parameterised queries or prepared statements, validate "
            "and canonicalise input server-side, and grant the database account least privilege."
        ),
        evidence=full_poc(evidence),
        source_tool="sqlmap",
    )


def _path_finding(path: str, status: str, size: str, target: str, tool: str,
                  evidence: str) -> Optional[Finding]:
    if status not in _INTERESTING_STATUS:
        return None
    path = path if path.startswith("/") else "/" + path
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
    return Finding(
        title=(f"Exposed path discovered: {path} (HTTP {status})" if sensitive
               else f"Discovered path: {path} (HTTP {status})"),
        severity=sev,
        target=target,
        description=(
            f"Directory brute-force against {target} found {path} responding with HTTP {status}"
            + (f" ({size} bytes)" if size else "")
            + (". The path name indicates potentially sensitive content." if sensitive else ".")
        ),
        remediation=(
            "Remove or relocate the resource if it is not intended to be public, disable directory "
            "listing, and restrict access at the web server or WAF." if sensitive else
            "No action required if this page is meant to be public; it is recorded as part of "
            "the discovered attack surface."
        ),
        evidence=evidence.strip(),
        source_tool=tool,
    )


def _cred_finding(svc: str, host: str, port: str, user: str, tool: str) -> Finding:
    where = f"{host}:{port}" if port else host
    web = svc.lower().startswith(("http", "https"))
    return Finding(
        # Set here, not by the shared template, whose "brute force" steps
        # tell an SSH or RDP service to add a CAPTCHA.
        remediation_actionable=(
            f"1. Change the password of '{user}' on {where} now, and on every other system that shares it. "
            f"2. Enforce a password policy that rejects dictionary and default passwords. "
            + ("3. Add login rate limiting and account lockout (or CAPTCHA) to the web login. "
               if web else
               f"3. Limit failed {svc} logins (for example fail2ban, or the service's own lockout setting). ")
            + ("4. For SSH, switch to key-based authentication and set PasswordAuthentication no. "
               if svc.lower() == "ssh" else "4. Restrict the service to the networks that need it. ")
            + f"5. Re-run {tool} with the same wordlist to confirm the login no longer succeeds."
        ),
        title=f"Valid credentials recovered by brute force: {svc} {user}@{where}",
        severity="CRITICAL",
        target=where,
        description=(
            f"{tool} successfully authenticated to the {svc} service on {where} using the "
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
        evidence=(f"[{port}][{svc}] " if port else f"[{svc}] ")
                 + f"host: {host}   login: {user}   password: <redacted>",
        source_tool=tool,
        is_pii_exposed=True,
    )


def _wp_core(version: str, note: str, target: str, evidence: str) -> Finding:
    insecure = "insecure" in note.lower() or "outdated" in note.lower()
    return Finding(
        title=f"WordPress {version} identified ({note.strip()[:60]})",
        severity="HIGH" if insecure else "INFO",
        # Running a release with published vulnerabilities is A06; the title
        # names no vulnerability class, so the keyword pass said Misconfiguration.
        category="Vulnerable Components" if insecure else "",
        remediation_actionable=(
            "1. Back up the site, then update WordPress core to the current release (Dashboard > Updates, "
            "or 'wp core update'). 2. Enable automatic minor/security updates. "
            "3. Re-run WPScan to confirm the version is no longer reported insecure."
        ) if insecure else "",
        target=target,
        description=f"WPScan identified WordPress {version} on {target}. Scanner note: {note.strip()}.",
        remediation="Upgrade WordPress core to the current supported release.",
        evidence=evidence,
        source_tool="WPScan",
    )


def _wp_component(title: str) -> str:
    """"Contact Form 7 < 5.3.2 - Unrestricted File Upload" -> "Contact Form 7";
    "WordPress 5.0-5.2.2 - Authenticated Stored XSS" -> "WordPress"."""
    name = re.split(r'\s+-\s+', title, maxsplit=1)[0].strip()
    name = re.sub(r'\s*(?:(?:<=?|≤|>=?)\s*\d[\w.]*|\d+\.[\w.]*(?:\s*-\s*\d[\w.]*)?)$', '', name).strip()
    return name or "the affected component"


def _wp_vuln(title: str, cves: List[str], fixed: str, target: str, kind: str = "") -> Finding:
    component = _wp_component(title)
    # WordPress's own vulnerabilities are fixed by a core update; the command
    # for a plugin is not the command for core.
    if not kind:
        kind = "core" if component.lower() == "wordpress" else ""
    how = {"core": "Dashboard > Updates, or 'wp core update'",
           "plugin": "the Plugins page, or 'wp plugin update <slug>'",
           "theme": "the Themes page, or 'wp theme update <slug>'"}.get(
        kind, "the WordPress admin, or 'wp plugin update' / 'wp theme update'")
    dangerous = re.search(r'remote code execution|\brce\b|file upload|sql injection|'
                          r'authentication bypass|privilege escalation', title, re.IGNORECASE)
    fixed = (fixed or "").strip()
    return Finding(
        title=f"WordPress vulnerability: {title[:100]}",
        severity="HIGH" if (cves or dangerous) else "MEDIUM",
        cve_list=list(cves),
        target=target,
        # A published vulnerability in a component the site runs: A06.
        category="Vulnerable Components",
        description=f"WPScan reported '{title}' against {target}." + (f" Fixed in {fixed}." if fixed else ""),
        remediation=f"Update {component}" + (f" to {fixed} or later." if fixed else " to the latest release."),
        # The flaw is in a third-party theme/plugin, so the developer's
        # step is the vendor update. The keyword templates answered
        # "file upload" with how to write a safe upload handler.
        remediation_actionable=(
            f"1. Update {component}"
            + (f" to {fixed} or later" if fixed else " to the latest release")
            + f" from {how}. "
            + ("2. Until the update is applied, restrict access to wp-admin and apply any mitigation in the advisory. "
               if kind == "core" else
               "2. If no update can be applied, deactivate and remove it. ")
            + "3. Re-run WPScan to confirm the vulnerability is no longer reported."
        ),
        evidence=title,
        source_tool="WPScan",
    )


# WPScan "Interesting Finding(s)": JSON type, console phrase, severity, title, fix.
_WP_INTERESTING = (
    ("xmlrpc", r"XML-RPC seems to be enabled", "LOW", "WordPress XML-RPC interface enabled",
     "Disable XML-RPC if unused, or block xmlrpc.php at the web server or WAF.",
     "It allows many password guesses per request and pingback-based reflection."),
    ("readme", r"WordPress readme found", "INFO", "WordPress readme.html exposed",
     "Remove readme.html from the web root.", "It discloses the WordPress version."),
    ("upload_directory_listing", r"Upload directory has listing enabled", "MEDIUM",
     "WordPress upload directory listing enabled",
     "Disable directory listing on wp-content/uploads (Apache 'Options -Indexes').",
     "Every uploaded file can be browsed and downloaded."),
    ("debug_log", r"Debug Log found", "MEDIUM", "WordPress debug log exposed",
     "Remove wp-content/debug.log and set WP_DEBUG_LOG to false in production.",
     "It can disclose paths, queries and credentials."),
    ("backup_db", r"A backup directory has been found|Database backup", "HIGH",
     "WordPress database backup exposed",
     "Remove the backup from the web root and store backups outside it.",
     "A database backup contains user password hashes and site data."),
    ("registration", r"Registration is enabled", "LOW", "WordPress user registration enabled",
     "Disable 'Anyone can register' unless the site needs public sign-up.",
     "Anyone can create an account on the site."),
    ("full_path_disclosure", r"Full Path Disclosure", "LOW", "WordPress full path disclosure",
     "Set display_errors to Off in production.", "The server's file system path is disclosed."),
    ("wp_cron", r"The external WP-Cron seems to be enabled", "INFO", "WordPress external WP-Cron enabled",
     "Disable external WP-Cron (DISABLE_WP_CRON) and run cron from the system scheduler.",
     "wp-cron.php can be requested by anyone and used to load the server."),
)


def _wp_interesting(kind: str, url: str, target: str, evidence: str) -> Optional[Finding]:
    for jtype, _phrase, sev, title, fix, why in _WP_INTERESTING:
        if kind == jtype:
            return Finding(
                title=title, severity=sev, target=target,
                description=f"WPScan found this at {url}. {why}",
                remediation=fix, evidence=evidence, source_tool="WPScan")
    return None


def _wp_outdated(kind: str, name: str, version: str, latest: str, target: str, evidence: str) -> Finding:
    return Finding(
        title=(f"Outdated WordPress {kind}: {name}" + (f" {version}" if version else "")
               + f" (latest {latest})"),
        severity="LOW",
        target=target,
        description=f"WPScan reports the {kind} '{name}' is out of date; the latest version is {latest}.",
        remediation=f"Update the {kind} to {latest} or later, or remove it if unused.",
        evidence=evidence, source_tool="WPScan")


def _wp_users(users: List[str], target: str) -> Finding:
    return Finding(
        title=f"WordPress user enumeration: {', '.join(users[:10])}",
        severity="LOW",
        target=target,
        description=(f"WPScan enumerated {len(users)} account name(s), giving an attacker "
                     f"half of every login pair: {', '.join(users[:10])}."),
        remediation=("Block author-archive and REST API user enumeration (/?author=N, "
                     "/wp-json/wp/v2/users) and enforce strong passwords with lockout."),
        evidence="User(s) Identified: " + ", ".join(users), source_tool="WPScan")


class KaliParser(BaseParser):
    """Parses the output of common Kali Linux assessment tools, in every format they write."""

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

        handler = {
            "nikto": self._parse_nikto,
            "nikto_csv": self._parse_nikto_csv,
            "nikto_xml": self._parse_nikto_xml,
            "nikto_json": self._parse_nikto_json,
            "sqlmap": self._parse_sqlmap,
            "sqlmap_csv": self._parse_sqlmap_csv,
            "gobuster": self._parse_gobuster,
            "dirb": self._parse_dirb,
            "ffuf": self._parse_ffuf,
            "ffuf_json": self._parse_ffuf_json,
            "feroxbuster": self._parse_feroxbuster,
            "hydra": self._parse_hydra,
            "hydra_json": self._parse_hydra_json,
            "medusa": self._parse_medusa,
            "wpscan": self._parse_wpscan,
            "wpscan_json": self._parse_wpscan_json,
            "enum4linux": self._parse_enum4linux,
            "masscan": self._parse_masscan,
        }[tool]

        findings = [f for f in handler(content) if f is not None]

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
    def _parse_nikto(self, content: str) -> List[Finding]:
        out = []
        # One run can scan several hosts; each block opens with "+ Target IP:".
        blocks = re.split(r'(?m)^(?=\+ Target IP:)', content)
        for block in blocks:
            ip = re.search(r'^\+ Target IP:\s*(\S+)', block, re.MULTILINE)
            host = re.search(r'^\+ Target Hostname:\s*(\S+)', block, re.MULTILINE)
            port = re.search(r'^\+ Target Port:\s*(\d+)', block, re.MULTILINE)
            target = (_host_label(host.group(1) if host else "", ip.group(1) if ip else "",
                                  port.group(1) if port else "")
                      if (ip or host) else _target_from(content))
            for line in block.splitlines():
                s = line.strip()
                if not s.startswith("+"):
                    continue
                out.append(_nikto_finding(s.lstrip("+ ").strip(), target, s))
        return out

    def _parse_nikto_csv(self, content: str) -> List[Finding]:
        # nikto -Format csv: "host","ip","port","reference","method","uri","message",
        # after a '"Nikto - v2.1.6/2.1.5"' banner row (2.5 writes a header row instead).
        out = []
        for row in csv.reader(io.StringIO(content)):
            if len(row) < 7 or row[0].lower() in ("host ip", "hostname"):
                continue
            host, ip, port, ref, method, uri, msg = (c.strip() for c in row[:7])
            if not msg:
                continue
            body = _nikto_body(uri, msg)
            out.append(_nikto_finding(body, _host_label(host, ip, port),
                                      f"{method} {uri} {ref}: {msg}".replace("  ", " ").strip()))
        return out

    def _parse_nikto_xml(self, content: str) -> List[Finding]:
        import xml.etree.ElementTree as ET
        # The DOCTYPE names a local DTD file that is not present here.
        text = re.sub(r'<!DOCTYPE[^>]*>', '', content, count=1)
        try:
            root = ET.fromstring(text.strip())
        except ET.ParseError:
            return []
        out = []
        for sd in root.iter("scandetails"):
            target = _host_label(sd.get("targethostname", ""), sd.get("targetip", ""),
                                 sd.get("targetport", ""))
            for item in sd.iter("item"):
                msg = (item.findtext("description") or "").strip()
                uri = (item.findtext("uri") or "").strip()
                osvdb = item.get("osvdbid", "0")
                ref = f"OSVDB-{osvdb} " if osvdb not in ("", "0") else ""
                out.append(_nikto_finding(_nikto_body(uri, msg), target,
                                          f"{item.get('method', '')} {uri} {ref}: {msg}".strip()))
        return out

    def _parse_nikto_json(self, content: str) -> List[Finding]:
        data = _load_json(content)
        hosts = data if isinstance(data, list) else [data]
        out = []
        for h in hosts:
            if not isinstance(h, dict):
                continue
            target = _host_label(h.get("host", ""), h.get("ip", ""), h.get("port", ""))
            for v in h.get("vulnerabilities") or []:
                msg, uri = str(v.get("msg", "")), str(v.get("url", ""))
                out.append(_nikto_finding(_nikto_body(uri, msg), target,
                                          f"{v.get('method', '')} {uri}: {msg}".strip()))
        return out

    # ── sqlmap ──────────────────────────────────────────────────────────────
    def _parse_sqlmap(self, content: str) -> List[Finding]:
        target = _target_from(content)
        out = []
        dbms = re.search(r'back-end DBMS(?: is|:)\s*([^\n]+)', content, re.IGNORECASE)
        # A confirmed injection point is the headline result.
        for m in re.finditer(
            r'Parameter:\s*(?P<param>[^\s(]+)\s*\((?P<method>[A-Z]+)\)(?P<body>.*?)(?=\nParameter:|\n---|\Z)',
            content, re.DOTALL | re.IGNORECASE,
        ):
            body = m.group("body")
            types = [t.strip() for t in re.findall(r'Type:\s*([^\n]+)', body)]
            titles = re.findall(r'Title:\s*([^\n]+)', body)
            detail = titles[0].strip() if titles else (types[0] if types else "SQL injection")
            out.append(_sqli_finding(m.group("param"), m.group("method"), detail, types, target,
                                     dbms.group(1).strip() if dbms else "", body.strip()))

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

    def _parse_sqlmap_csv(self, content: str) -> List[Finding]:
        # results-<date>.csv, written with --batch/-m: one row per injectable
        # parameter; Technique(s) are sqlmap's letters (BEUSTQ).
        out = []
        for row in csv.DictReader(io.StringIO(content.strip())):
            url = (row.get("Target URL") or "").strip()
            param = (row.get("Parameter") or "").strip()
            if not url or not param:
                continue
            techniques = [_SQLMAP_TECHNIQUES.get(c, c) for c in (row.get("Technique(s)") or "").strip()]
            site, path = _site(url)
            out.append(_sqli_finding(param, (row.get("Place") or "").strip() or "GET",
                                     techniques[0] if techniques else "SQL injection", techniques,
                                     f"{site}{path}", evidence=", ".join(f"{k}: {v}" for k, v in row.items() if v)))
        return out

    # ── directory brute-forcers ─────────────────────────────────────────────
    def _parse_gobuster(self, content: str) -> List[Finding]:
        target = _target_from(content)
        return [
            _path_finding(m.group("path"), m.group("status"), m.group("size") or "", target,
                          "Gobuster", m.group(0))
            for m in re.finditer(
                r'^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d{3})\)(?:\s*\[Size:\s*(?P<size>\d+)\])?',
                content, re.MULTILINE)
        ]

    def _parse_dirb(self, content: str) -> List[Finding]:
        out = []
        for m in re.finditer(r'^\+ (?P<url>https?://\S+) \(CODE:(?P<status>\d{3})\|SIZE:(?P<size>\d+)\)',
                             content, re.MULTILINE):
            site, path = _site(m.group("url"))
            out.append(_path_finding(path, m.group("status"), m.group("size"), site, "dirb", m.group(0)))
        # "==> DIRECTORY:" is a directory dirb found and recursed into; it
        # prints no status, and a listed directory answered 200/301.
        for m in re.finditer(r'^==> DIRECTORY: (?P<url>https?://\S+)', content, re.MULTILINE):
            site, path = _site(m.group("url"))
            out.append(_path_finding(path.rstrip("/") or "/", "301", "", site, "dirb", m.group(0)))
        return out

    def _parse_ffuf(self, content: str) -> List[Finding]:
        url = re.search(r'::\s*URL\s*:\s*(\S+)', content)
        base = url.group(1) if url else _target_from(content)
        site, prefix = _site(base.replace("FUZZ", ""))
        out = []
        for m in re.finditer(r'^(?P<word>\S+)\s+\[Status: (?P<status>\d{3}), Size: (?P<size>\d+)',
                             content, re.MULTILINE):
            path = prefix.rstrip("/") + "/" + m.group("word").lstrip("/")
            out.append(_path_finding(path, m.group("status"), m.group("size"), site, "ffuf", m.group(0)))
        return out

    def _parse_ffuf_json(self, content: str) -> List[Finding]:
        out = []
        for r in (_load_json(content) or {}).get("results") or []:
            site, path = _site(str(r.get("url", "")))
            out.append(_path_finding(path, str(r.get("status", "")), str(r.get("length", "")), site, "ffuf",
                                     f"{r.get('url')} [Status: {r.get('status')}, Size: {r.get('length')}]"))
        return out

    def _parse_feroxbuster(self, content: str) -> List[Finding]:
        out = []
        for m in re.finditer(r'^(?P<status>\d{3})\s+[A-Z]+\s+\d+l\s+\d+w\s+(?P<size>\d+)c\s+(?P<url>https?://\S+)',
                             content, re.MULTILINE):
            site, path = _site(m.group("url"))
            out.append(_path_finding(path, m.group("status"), m.group("size"), site, "feroxbuster", m.group(0)))
        return out

    # ── credential attacks ──────────────────────────────────────────────────
    def _parse_hydra(self, content: str) -> List[Finding]:
        return [
            _cred_finding(m.group("svc"), m.group("host"), m.group("port"), m.group("user"), "Hydra")
            for m in re.finditer(
                r'^\[(?P<port>\d+)\]\[(?P<svc>[^\]]+)\]\s+host:\s*(?P<host>\S+)\s+login:\s*(?P<user>\S+)\s+password:\s*(?P<pw>\S+)',
                content, re.MULTILINE | re.IGNORECASE)
        ]

    def _parse_hydra_json(self, content: str) -> List[Finding]:
        return [
            _cred_finding(str(r.get("service", "")), str(r.get("host", "")), str(r.get("port", "")),
                          str(r.get("login", "")), "Hydra")
            for r in (_load_json(content) or {}).get("results") or [] if isinstance(r, dict) and r.get("login")
        ]

    def _parse_medusa(self, content: str) -> List[Finding]:
        return [
            _cred_finding(m.group("svc"), m.group("host"), "", m.group("user"), "Medusa")
            for m in re.finditer(r'^ACCOUNT FOUND:\s*\[(?P<svc>\w+)\]\s*Host:\s*(?P<host>\S+)\s+'
                                 r'User:\s*(?P<user>\S+)\s+Password:\s*\S*\s*\[SUCCESS\]', content, re.MULTILINE)
        ]

    # ── wpscan ──────────────────────────────────────────────────────────────
    def _parse_wpscan(self, content: str) -> List[Finding]:
        target = _target_from(content)
        out = []

        m = re.search(r'WordPress version ([\d.]+) identified\s*\(([^)]*)\)', content, re.IGNORECASE)
        if m:
            out.append(_wp_core(m.group(1), m.group(2), target, m.group(0)))

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
            out.append(_wp_vuln(title, cves, fixed.group(1) if fixed else "", target))

        # "Interesting Findings" WPScan reports in their own sections.
        for jtype, phrase, *_rest in _WP_INTERESTING:
            m = re.search(rf'(?:{phrase})[^:\n]*:?\s*(\S*)', content, re.IGNORECASE)
            if m:
                out.append(_wp_interesting(jtype, m.group(1) or target, target, m.group(0).strip()))
        for bm in re.finditer(r'\[\+\]\s*(?:WordPress theme in use:\s*)?(?P<name>[\w.-]+)\s*\n'
                              r'(?P<body>(?:\s*\|[^\n]*\n)+)', content):
            body = bm.group("body")
            od = re.search(r'The version is out of date, the latest version is\s*([\w.]+)', body)
            if not od:
                continue
            ver = re.search(r'Version:\s*([\w.]+)', body)
            kind = "theme" if "/themes/" in body else ("plugin" if "/plugins/" in body else "component")
            out.append(_wp_outdated(kind, bm.group("name"), ver.group(1) if ver else "", od.group(1),
                                    target, od.group(0)))
        um = re.search(r'User\(s\) Identified:\s*\n(?P<body>(?:.*\n){0,40})', content)
        if um:
            users = re.findall(r'^\[\+\]\s*([^\s|]+)\s*$', um.group("body"), re.MULTILINE)
            users = [u for u in users if not u.lower().startswith(("finished", "requests", "enumerating"))]
            if users:
                out.append(_wp_users(users, target))
        return out

    def _parse_wpscan_json(self, content: str) -> List[Finding]:
        data = _load_json(content) or {}
        target = str(data.get("target_url") or data.get("effective_url") or "Target Host")
        out = []

        def _vulns(entries, kind):
            for v in entries or []:
                refs = v.get("references") or {}
                cves = sorted({("CVE-" + c if not str(c).upper().startswith("CVE-") else str(c)).upper()
                               for c in refs.get("cve") or []})
                out.append(_wp_vuln(str(v.get("title", "")), cves, str(v.get("fixed_in") or ""), target, kind))

        ver = data.get("version") or {}
        if ver.get("number"):
            status = str(ver.get("status") or "")
            note = status.capitalize() + (f", released on {ver['release_date']}" if ver.get("release_date") else "")
            out.append(_wp_core(str(ver["number"]), note, target,
                                f"WordPress version {ver['number']} identified ({note})"))
            _vulns(ver.get("vulnerabilities"), "core")

        for itf in data.get("interesting_findings") or []:
            out.append(_wp_interesting(str(itf.get("type", "")), str(itf.get("url", "")), target,
                                       str(itf.get("to_s", ""))))

        components = []
        if isinstance(data.get("main_theme"), dict):
            components.append(("theme", data["main_theme"]))
        for kind, key in (("theme", "themes"), ("plugin", "plugins")):
            for comp in (data.get(key) or {}).values():
                if isinstance(comp, dict):
                    components.append((kind, comp))
        for kind, comp in components:
            name = str(comp.get("slug", ""))
            version = str((comp.get("version") or {}).get("number") or "")
            if comp.get("outdated") and comp.get("latest_version"):
                out.append(_wp_outdated(kind, name, version, str(comp["latest_version"]), target,
                                        f"The version is out of date, the latest version is {comp['latest_version']}"))
            _vulns(comp.get("vulnerabilities"), kind)

        users = list((data.get("users") or {}).keys())
        if users:
            out.append(_wp_users(users, target))
        return out

    # ── SMB enumeration ─────────────────────────────────────────────────────
    def _parse_enum4linux(self, content: str) -> List[Finding]:
        m = (re.search(r'^Target \.+ (\S+)', content, re.MULTILINE)
             or re.search(r'(?:Session Check|Target Information) on (\S+?)\s*\)?\s*$', content, re.MULTILINE))
        target = m.group(1) if m else _target_from(content)
        out = []
        if re.search(r"allows sessions? using username '', password ''", content):
            out.append(Finding(
                title="SMB null session permitted",
                severity="MEDIUM",
                target=target,
                description=(f"The SMB service on {target} accepts an anonymous (null) session, letting "
                             f"anyone enumerate users, groups, shares and the password policy."),
                remediation=("Disable anonymous access: set 'restrict anonymous = 2' (Samba) or "
                             "RestrictAnonymous=1 and RestrictAnonymousSAM=1 (Windows)."),
                evidence="Server allows sessions using username '', password ''",
                source_tool="enum4linux"))
        # enum4linux: "//host/share  Mapping: OK Listing: OK Writing: N/A"
        # enum4linux-ng: "Testing share public" then "Mapping: OK, Listing: OK"
        shares = [(s, w) for s, w in re.findall(
            r'^//[^/\s]+/(\S+)\s+Mapping: OK,? Listing: OK(?:,? Writing: (\w+))?', content, re.MULTILINE)]
        shares += [(s, "") for s in re.findall(
            r'Testing share (\S+)\s*\n\s*\[\+\]\s*Mapping: OK, Listing: OK', content)]
        for share, writing in shares:
            if share.upper() == "IPC$":
                continue
            writable = writing.upper() == "OK"
            out.append(Finding(
                title=f"Anonymous {'write' if writable else 'read'} access to SMB share '{share}'",
                severity="HIGH" if writable else "MEDIUM",
                target=target,
                description=(f"The share '{share}' on {target} can be mapped and listed without "
                             f"credentials" + (" and written to." if writable else ".")),
                remediation="Remove guest/anonymous access from the share and grant access to named accounts only.",
                evidence=f"//{target}/{share} Mapping: OK Listing: OK" + (" Writing: OK" if writable else ""),
                source_tool="enum4linux"))
        users = sorted(set(re.findall(r'user:\[([^\]]+)\]\s*rid:', content)))
        if users:
            out.append(Finding(
                title=f"SMB user enumeration: {', '.join(users[:10])}",
                severity="LOW",
                target=target,
                description=f"{len(users)} account name(s) were enumerated over SMB: {', '.join(users[:10])}.",
                remediation="Disable anonymous SAM enumeration (RestrictAnonymousSAM=1 / 'restrict anonymous = 2').",
                evidence="; ".join(f"user:[{u}]" for u in users), source_tool="enum4linux"))
        minlen = re.search(r'Minimum password length:\s*(\d+)', content)
        if minlen and int(minlen.group(1)) < 8:
            out.append(Finding(
                title=f"Weak domain password policy: minimum length {minlen.group(1)}",
                severity="MEDIUM", target=target,
                description=f"The password policy read over SMB allows passwords of {minlen.group(1)} characters.",
                remediation="Require a minimum password length of at least 12 characters.",
                evidence=minlen.group(0), source_tool="enum4linux"))
        lockout = re.search(r'Account Lockout Threshold:\s*(None|0)\b', content)
        if lockout:
            out.append(Finding(
                title="No account lockout threshold",
                severity="MEDIUM", target=target,
                description="The password policy read over SMB sets no lockout threshold, so passwords can be guessed without limit.",
                remediation="Set an account lockout threshold (for example 5-10 failed attempts).",
                evidence=lockout.group(0), source_tool="enum4linux"))
        return out

    # ── masscan ─────────────────────────────────────────────────────────────
    def _parse_masscan(self, content: str) -> List[Finding]:
        ports = {}
        for m in re.finditer(r'Discovered open port (\d+)/(tcp|udp) on (\S+)', content):
            ports.setdefault(m.group(3), []).append((m.group(1), m.group(2)))
        for m in re.finditer(r'^open (tcp|udp) (\d+) (\S+)', content, re.MULTILINE):     # -oL
            ports.setdefault(m.group(3), []).append((m.group(2), m.group(1)))
        out = []
        for host, plist in ports.items():
            plist = sorted(set(plist), key=lambda p: (p[1], int(p[0])))
            for port, proto in plist:
                if proto == "tcp" and port in _RISKY_PORTS:
                    sev, label = _RISKY_PORTS[port]
                    out.append(Finding(
                        title=f"{label} ({port}/tcp)", severity=sev, target=host,
                        description=(f"masscan found {port}/tcp open on {host}, the standard port of a "
                                     f"service that carries credentials and sessions in clear text. "
                                     f"masscan does not confirm the service; verify with a service scan."),
                        remediation="Disable the service and use SSH instead; if it must stay, restrict it to a management network.",
                        remediation_actionable=_cleartext_login_steps(port, host),
                        evidence=f"Discovered open port {port}/tcp on {host}",
                        source_tool="masscan", confidence="Tentative"))
            # Open ports are the scan's inventory: recorded, not rated.
            out.append(Finding(
                title=f"Open ports on {host}: {', '.join(f'{p}/{t}' for p, t in plist)}",
                severity="INFO", target=host,
                description=f"masscan found {len(plist)} open port(s) on {host}.",
                remediation="Confirm each open port is required and restricted to the networks that need it.",
                evidence="\n".join(f"Discovered open port {p}/{t} on {host}" for p, t in plist),
                source_tool="masscan"))
        return out
