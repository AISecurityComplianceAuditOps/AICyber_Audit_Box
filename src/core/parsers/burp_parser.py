# -*- coding: utf-8 -*-
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

# Phrases that mean the surrounding sentence is NOT reporting a live vulnerability:
# it is remediation advice, a recommendation, or a statement that the issue is closed.
# The PoC regex matches on a vulnerability NAME, which appears just as often in
# "SQL injection prevention should be in place" as in an actual finding.
_POC_NON_FINDING_PHRASES = (
    "are fixed", "is fixed", "was fixed", "has been fixed", "have been fixed",
    "resolved", "mitigated", "remediated", "patched", "no longer",
    "should be", "must be", "recommend", "prevention", "prevented",
    "best practice", "guideline", "not found", "not observed", "not identified",
    "no instances", "none found", "protect against", "to prevent",
)


def _is_non_finding_poc(text: str) -> bool:
    """True when a PoC keyword hit is advice or a closure note rather than a finding.

    Confirmed on two real pentest reports: the regex matched inside
    "SQL injection( All Application exposed API's are fixed) and" and
    "SQL injection prevention should be in place, Session management and ident...",
    and both were emitted as HIGH severity findings. A tool that invents HIGH
    vulnerabilities out of sentences saying they were fixed is worse than one that
    reports nothing -- and the caller already warns when a parser claims a file but
    extracts zero findings, which is the honest outcome here.
    """
    low = (text or "").lower()
    return any(p in low for p in _POC_NON_FINDING_PHRASES)


_PDF_ARTIFACT_PATTERNS = (
    # Browser print header/footer: the source document's own file:// URL. Leaks the
    # exporting machine's directory structure straight into the customer's report --
    # observed as "file:///C:/Users/<name>/Desktop/.../portswigger_sample.html" inside
    # a delivered finding's description.
    re.compile(r'file:///\S+', re.IGNORECASE),
    # Print pagination stamped beside that URL ("24/62"). Bounded to 1-3 digits each
    # side so real ratios in scanner output (e.g. a 1024/2048 key size) are untouched.
    re.compile(r'(?<!\d)\d{1,3}\s*/\s*\d{1,3}(?=\s|$)'),
    # about:blank appears in some headless-Chrome exports in place of the file URL.
    re.compile(r'\babout:blank\b', re.IGNORECASE),
)


# Section terminators for the flat-text (PDF) path. Deliberately newline-free:
# printed-to-PDF text has no reliable line breaks, so anchoring on "\nIssue
# background" made every terminator unmatchable. Each alternative below is a
# marker that genuinely ends an issue-detail section in a Burp export:
#   Issue background / remediation / References / Vulnerability classifications
#       -- the sibling sections Burp emits after the detail
#   Request N / Response N   -- the raw HTTP capture that follows the prose
#   <digits>. <Capital>      -- the next numbered finding's heading
_SECTION_END = (
    r'(?=Issue\s+(?:background|remediation)'
    r'|References\b'
    r'|Vulnerability\s+classifications'
    r'|(?:HTTP\s+)?Request\s+\d'
    r'|(?:HTTP\s+)?Response\s+\d'
    r'|\d{1,3}\.\s+[A-Z]'
    r'|$)'
)
_ISSUE_DETAIL_RE = r'Issue detail[s]?\s*[:\n]?\s*(.*?)' + _SECTION_END
_ISSUE_BACKGROUND_RE = r'Issue background\s*[:\n]?\s*(.*?)' + _SECTION_END

# Hard ceiling on a description, as a backstop for export shapes not seen here.
_MAX_DESC_CHARS = 1500


def _scrub_pdf_artifacts(text: str) -> str:
    """Removes browser print-to-PDF header/footer noise from extracted text.

    A Burp HTML report printed to PDF carries the print chrome into its text layer:
    the source file:// URL and the page counter. Those land inside finding
    descriptions verbatim, so this runs before any parsing rather than after --
    once the text is sliced into findings the artifacts are already embedded.
    """
    if not text:
        return text
    for pat in _PDF_ARTIFACT_PATTERNS:
        text = pat.sub(' ', text)
    return text



# ── What a visual proof of concept is actually reporting ────────────────────
# A finding recovered from a screenshot has no scanner metadata behind it, so
# its description used to be the matched text repeated back:
#
#     "OCR extracted vulnerability proof-of-concept: Vulnerability Proof Stored XSSI"
#
# which tells a reader nothing they had not already seen in the title, and
# carries an OCR artefact into the customer's report. Where the match names a
# vulnerability class, the class is described instead.
#
# Matched with a tolerant suffix: the PoC regex ends in [A-Z]* precisely because
# OCR runs the class name into the next character ("Stored XSS]" read as
# "XSSI"), so the class has to be recognised through that.
_POC_CLASSES = (
    # (pattern, class name, description, remediation, developer steps)
    (r'sql\s*injection|sqli', "SQL Injection",
     "User-supplied input reaches a SQL query without parameterisation, so an "
     "attacker can alter the query's structure. Depending on the query this "
     "allows reading or modifying data the application should not expose, and "
     "in some configurations command execution on the database host.",
     "Use parameterised queries (prepared statements) for every database call so input can never be parsed as SQL. Where dynamic identifiers are unavoidable, validate them against an allow-list. Grant the application's database account only the privileges it needs.",
     "1. Replace string-concatenated SQL with parameterised queries or the ORM's bound-parameter API. 2. Allow-list any dynamic table or column names. 3. Reduce the application database user's privileges. 4. Re-test the same endpoint with the original payload."),
    (r'stored\s*xss|persistent\s*xss', "Stored Cross-Site Scripting",
     "Attacker-supplied script is stored by the application and returned to "
     "other users without being encoded for its output context, so it executes "
     "in each victim's browser under the application's origin. It is commonly "
     "used to steal session cookies and act as the victim.",
     'Encode all stored user content for the context it is rendered into, at the point of output rather than on input. Do not render user content as HTML unless it has been sanitised with a vetted library. Add a Content-Security-Policy that forbids inline script, and set session cookies HttpOnly so they cannot be read by script.',
     '1. Apply context-aware output encoding where the stored field is rendered. 2. If HTML is genuinely required, sanitise it server-side with a maintained allow-list sanitiser. 3. Set HttpOnly, Secure and SameSite on session cookies. 4. Deploy a Content-Security-Policy that blocks inline script. 5. Re-submit the original payload and confirm it is rendered as text.'),
    (r'reflected\s*xss', "Reflected Cross-Site Scripting",
     "Input from the request is echoed into the response without output "
     "encoding, so a crafted link executes script in the victim's browser under "
     "the application's origin, commonly to steal session cookies.",
     'Encode request-derived values for the context they are written into, at the point of output. Add a Content-Security-Policy that forbids inline script, and set session cookies HttpOnly.',
     '1. Apply context-aware output encoding to every reflected parameter. 2. Set HttpOnly, Secure and SameSite on session cookies. 3. Deploy a Content-Security-Policy that blocks inline script. 4. Re-test with the original crafted URL.'),
    (r'dom[\s-]*based\s*xss', "DOM-Based Cross-Site Scripting",
     "Client-side script writes untrusted input into a dangerous sink, so the "
     "payload executes in the victim's browser without the server ever seeing "
     "it.",
     'Avoid writing untrusted values into dangerous sinks (innerHTML, document.write, eval). Use textContent or a framework binding that escapes by default, and add a Content-Security-Policy that forbids inline script.',
     '1. Replace innerHTML / document.write / eval with textContent or a safe framework binding. 2. Validate any value taken from location, referrer or postMessage. 3. Deploy a Content-Security-Policy. 4. Re-test the payload.'),
    (r'cross[\s-]*site\s*scripting|xss', "Cross-Site Scripting",
     "Untrusted input is rendered without encoding for its output context, so "
     "script supplied by an attacker executes in a victim's browser under the "
     "application's origin, commonly to steal session cookies.",
     'Encode untrusted input for the context it is rendered into, at the point of output. Add a Content-Security-Policy that forbids inline script, and set session cookies HttpOnly so they cannot be read by script.',
     '1. Apply context-aware output encoding wherever the value is rendered. 2. Set HttpOnly, Secure and SameSite on session cookies. 3. Deploy a Content-Security-Policy that blocks inline script. 4. Re-test the payload.'),
    (r'cross[\s-]*site\s*request\s*forgery|csrf', "Cross-Site Request Forgery",
     "A state-changing request is accepted without a token tying it to the "
     "user's session, so another site can cause the victim's browser to perform "
     "it while authenticated.",
     'Require an anti-CSRF token on every state-changing request and verify it server-side. Set SameSite on session cookies, and re-authenticate for sensitive operations.',
     '1. Issue a per-session anti-CSRF token and verify it on every POST, PUT, PATCH and DELETE. 2. Set SameSite=Lax or Strict on session cookies. 3. Re-authenticate before sensitive actions. 4. Replay the original cross-site request and confirm it is rejected.'),
    (r'command\s*injection|os\s*command', "OS Command Injection",
     "User-supplied input reaches a shell command, allowing an attacker to run "
     "commands on the host with the application's privileges.",
     'Do not pass user input to a shell. Call the target program directly with an argument array, and validate any user-supplied argument against an allow-list. Run the application with least privilege.',
     "1. Replace shell invocations with a direct exec that takes an argument array. 2. Allow-list any user-controlled argument. 3. Drop the process's privileges. 4. Re-test with the original payload."),
    (r'path\s*traversal|directory\s*traversal', "Path Traversal",
     "A file path is built from user input without constraining it to the "
     "intended directory, so an attacker can read files elsewhere on the host.",
     'Resolve the requested path and confirm it stays inside the intended directory before opening it. Prefer an identifier that maps to a file server-side over accepting a path from the user.',
     '1. Canonicalise the path and reject anything outside the base directory. 2. Replace user-supplied paths with an indirect identifier where possible. 3. Re-test with traversal sequences.'),
    (r'ssrf|server[\s-]*side\s*request\s*forgery', "Server-Side Request Forgery",
     "The application fetches a URL supplied by the user, so an attacker can "
     "reach internal services that are not otherwise exposed.",
     'Validate the destination against an allow-list of permitted hosts and schemes, resolve it before use, and block internal address ranges and cloud metadata endpoints. Do not follow redirects to unvalidated hosts.',
     '1. Allow-list permitted hosts and schemes. 2. Resolve the host and reject private, loopback and link-local ranges. 3. Disable or re-validate redirects. 4. Re-test against an internal address.'),
)


def _describe_poc(match_str: str):
    """(name, description, remediation, steps) for a match, or four Nones.

    Ordered most specific first: "stored xss" must be recognised as stored XSS
    rather than falling through to the generic cross-site scripting entry.
    """
    text = str(match_str or "").lower()
    for pattern, name, description, remediation, steps in _POC_CLASSES:
        if re.search(r'(?<![a-z0-9])(?:' + pattern + r')', text):
            return name, description, remediation, steps
    return None, None, None, None


def _clean_poc_title(raw: str) -> str:
    """Trim a screenshot/PoC title down to the vulnerability name.

    The PoC regex grabs up to 60 characters after its keyword, which is fine for a
    prose report but not for a .docx: doc_parsers flattens table rows into
    "cell | cell | cell", so the run swallows the neighbouring severity and status
    columns and the 60-char cap then cuts mid-word. Real titles produced from the
    WAVE and Sample pentest reports:

        "Visual PoC: XSS vulnerability | High | No."
        "Visual PoC: Cross-site scripting (DOM-based) [WCSR] | Low "
        "Visual PoC: SQL injection( All Application exposed API's a"

    Those go into the customer's report verbatim. Cut at the column separator, drop
    a bracket the cap left unclosed, and drop a trailing partial word.
    """
    if not raw:
        return ""
    t = str(raw).split("|")[0]                      # table separator ends the title
    t = re.sub(r'\s+', ' ', t).strip()
    if t.count("(") > t.count(")"):                 # "SQL injection( All Application..."
        t = t[:t.rindex("(")].strip()
    if t.count("[") > t.count("]"):
        t = t[:t.rindex("[")].strip()
    t = re.sub(r',\s*\w{1,2}$', '', t)              # "...in place, S" -> "...in place"
    t = re.sub(r'[\s,;:\-]+$', '', t)
    return t.strip()


# ── Section anchoring for Burp PDF exports ───────────────────────────────────
#
# A Burp PDF opens every issue with its heading followed by the page's
# navigation links, and every instance of a multi-instance issue the same way:
#
#     1. SQL injection                    <- the ISSUE
#     Next
#     There are 3 instances of this issue:  ... Issue background ...
#     Issue remediation ... Vulnerability classifications  CWE-89 ...
#     1.1. https://.../catalog/filter [category parameter]   <- an INSTANCE
#     Previous Next
#     Summary  Severity: High  Confidence: Firm  ... Issue detail ...
#
# The table of contents lists the same headings WITHOUT the navigation line,
# which is what tells the two apart.
#
# Findings used to be titled from the nearest URL in the 600 characters BEFORE
# their severity line. For an issue with no instances of its own, that text
# belonged to the previous issue, so on a real report XML external entity
# injection was published as "/catalog/search/2 [term parameter]", client-side
# template injection as "/catalog [Referer HTTP header]", and the vulnerable
# JavaScript dependency as "/catalog/product". The wrong title then also missed
# its own CVSS rule, so the score was wrong too.
#
# And because the remediation and the CWE list sit in the ISSUE's section, not
# in each instance's, 25 of 35 findings on that report had no remediation and
# 34 had no CWE, though the report states both for every issue.
_BURP_ISSUE_RE = re.compile(r"(?m)^\s*(\d{1,3})\.\s+(\S[^\n]{1,160}?)\s*\n\s*(?:Previous|Next)\b")
_BURP_INSTANCE_RE = re.compile(
    r"(?m)^\s*(\d{1,3})\.(\d{1,3})\.\s+(\S[^\n]{0,300}?)\s*\n\s*(?:Previous|Next)\b")
_BURP_REMEDIATION_RE = re.compile(
    r"Issue remediation\s*\n(.*?)(?=\n\s*(?:References|Vulnerability classifications"
    r"|Request\s+1|Response\s+1)\b|\Z)", re.DOTALL | re.IGNORECASE)
_BURP_CLASSIFICATIONS_RE = re.compile(
    r"Vulnerability classifications\s*\n(.*?)(?=\n\s*(?:Request\s+1|Response\s+1|Request\b|"
    r"\d{1,3}\.\d{1,3}\.\s)|\Z)", re.DOTALL | re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-(\d{1,5})\b", re.IGNORECASE)

# CVSS v3 bands. The report's own severity is authoritative; an estimated score
# is kept inside the band that severity names so the two never contradict.
_SEVERITY_BANDS = {
    "CRITICAL": (9.0, 10.0),
    "HIGH": (7.0, 8.9),
    "MEDIUM": (4.0, 6.9),
    "LOW": (0.1, 3.9),
    "INFO": (0.0, 0.0),
}


def _burp_sections(content):
    """(issues, instances) located by their navigation-anchored headings.

    issues:    [(start, num, title)]
    instances: [(start, issue_num, url_and_param)]
    Returns ([], []) when the document is not shaped like a Burp PDF, so the
    caller keeps its previous behaviour for every other export.
    """
    issues = [(m.start(), m.group(1), m.group(2).strip())
              for m in _BURP_ISSUE_RE.finditer(content)
              if not m.group(2).strip().lower().startswith(("http", "/"))]
    instances = [(m.start(), m.group(1), m.group(3).strip())
                 for m in _BURP_INSTANCE_RE.finditer(content)]
    return issues, instances


def _clamp_to_band(score, severity):
    lo, hi = _SEVERITY_BANDS.get(severity, (0.0, 10.0))
    try:
        s = float(score)
    except (TypeError, ValueError):
        return score
    return round(min(max(s, lo), hi), 1)


class BurpParser(BaseParser):
    def can_parse(self, filename: str, content: str) -> bool:
        """Content-signature based detection — 0% filename keyword dependency.
        Images are immediately rejected regardless of their filename (a screenshot
        named 'shot_burp_sqli.png' must never match this parser).
        Detection is based on structural XML/HTML tags and content keywords that
        are exclusive to real Burp Suite / OWASP ZAP report exports.
        """
        if not content:
            return False
        # Guard 1: Reject image files immediately — images are visual PoC evidence,
        # never XML/HTML tool exports. This fixes the false-positive where a screenshot
        # named 'shot_burp_sqli.png' triggered BurpParser just because 'burp' was in
        # the filename.
        if is_image_file(filename):
            return False
        # Guard 2: Content-signature detection. These structural markers are
        # exclusively present in real Burp/ZAP reports. Scans the FULL content,
        # not a fixed-size prefix -- a real 2.1MB Nessus-shaped HTML export was
        # found (during verification testing) to have its actual signal content
        # starting at character ~160,000, past a 100K sample window, because a
        # large embedded <style> block sits before it. The same risk applies to
        # any styled HTML scanner export, so no fixed prefix window is safe here.
        sample = content.lower()
        # STRUCTURE, not a tool's name. This used to accept any document that
        # merely said "burp suite" or "owasp zap" -- and every human-written
        # pentest report names the tools it used. A real report listing
        #
        #     6. Auditing Tools:  1. Nmap  2. Kali Linux  3. Burp Suite
        #
        # was claimed as a Burp export, and its six real findings were replaced
        # by one invented "VAPT Finding" rated LOW. Only a Burp or ZAP export
        # itself carries these section markers; a report ABOUT a test does not.
        if ("<issues" in sample
                or "issue background" in sample
                or "issue detail" in sample
                or "burp collaborator" in sample
                or "portswigger.net" in sample
                or "<owaspzapreport" in sample
                or "<alertitem" in sample):
            return True
        return False

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], List[Finding]]:
        if not content:
            return [], []

        # Strip print-to-PDF chrome before anything slices the text into findings.
        # Harmless for XML/HTML input (the patterns don't occur there), required for
        # the text path, where these artifacts otherwise end up inside descriptions.
        content = _scrub_pdf_artifacts(content)

        # Check if content is XML format
        if content.strip().startswith("<?xml") or "<issues" in content[:2000]:
            return self._parse_xml(content)
        
        # HTML format parsing
        res_act, res_inf = self._parse_html(content)
        if res_act or res_inf:
            return res_act, res_inf
            
        # Fallback to plain-text / PDF text parsing
        return self._parse_plaintext(content)

    def _calculate_score(self, severity: str, confidence: str) -> float:
        score, _ = self._calculate_score_and_vector("", severity, confidence)
        return score

    def _calculate_score_and_vector(self, vuln_title: str, severity: str, confidence: str) -> Tuple[float, str]:
        t_lower = (vuln_title or "").lower()
        sev_upper = (severity or "").strip().upper()

        # Respect Burp's own explicit Informational assessment FIRST, before any
        # title-keyword match. Previously a Burp-reported Informational finding
        # whose title happened to contain e.g. "xss" or "sql injection" got
        # force-elevated to that keyword's fixed CVSS score regardless of what
        # Burp actually assessed -- this check used to run only as a fallback
        # after all the keyword branches below, so it could never actually fire
        # for a title matching any of them.
        if "INFORMATION" in sev_upper or "INFO" in sev_upper:
            return 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

        if "sql injection" in t_lower:
            return 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        elif "xml external entity" in t_lower or "xxe" in t_lower:
            return 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        elif "template injection" in t_lower or "csti" in t_lower:
            return 8.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
        elif "external service interaction (http)" in t_lower or "ssrf" in t_lower:
            return 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
        elif "cross-site scripting" in t_lower or "xss" in t_lower:
            return 7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        elif "open redirection" in t_lower or "open redirect" in t_lower:
            return 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        elif "javascript dependency" in t_lower or "cve-2020-7676" in t_lower:
            return 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        elif "autocomplete" in t_lower:
            return 3.5, "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        elif "strict transport security" in t_lower or "hsts" in t_lower:
            return 3.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"

        if "HIGH" in sev_upper:
            return 8.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        elif "MED" in sev_upper:
            return 5.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        elif "LOW" in sev_upper:
            return 2.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
        return 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

    def _parse_html(self, content: str) -> Tuple[List[Finding], List[Finding]]:
        soup = BeautifulSoup(content, _HTML_PARSER)
        actionable_findings: List[Finding] = []
        info_findings: List[Finding] = []

        bodh0s = soup.find_all('span', class_='BODH0')

        for b0 in bodh0s:
            cat_id = b0.get('id', '')
            raw_cat_title = b0.get_text().strip()
            cat_title = re.sub(r'^\d+\.\s*', '', raw_cat_title)
            next_b0 = b0.find_next('span', class_='BODH0')

            # Extract category-level background, remediation, and CWEs
            cat_bg, cat_remed = "", ""
            cat_cwes = []

            # Inspect headings following b0 up to next_b0
            for h2 in b0.find_all_next('h2'):
                if next_b0 and h2.sourceline and next_b0.sourceline and h2.sourceline > next_b0.sourceline:
                    break
                h2_text = h2.get_text().strip().lower()
                next_span = h2.find_next_sibling('span', class_='TEXT')
                txt_val = next_span.get_text().strip() if next_span else ""

                if "background" in h2_text and not cat_bg:
                    cat_bg = txt_val
                elif "remediation" in h2_text and not cat_remed:
                    cat_remed = txt_val
                elif "classifications" in h2_text or "references" in h2_text:
                    if next_span:
                        cwe_matches = re.findall(r'CWE-\d+', next_span.get_text())
                        cat_cwes.extend(cwe_matches)

            # Find child BODH1s under this BODH0
            b1_list = []
            for b1 in soup.find_all('span', class_='BODH1'):
                if b1.sourceline > b0.sourceline and (not next_b0 or b1.sourceline < next_b0.sourceline):
                    b1_list.append(b1)

            # Parse instance (helper function)
            def process_element(elem, is_b1=True) -> Finding:
                inst_id = elem.get('id', '')
                raw_inst_title = elem.get_text().strip()
                inst_title = re.sub(r'^\d+(\.\d+)?\.\s*', '', raw_inst_title)

                # Look for summary_table following elem
                st = elem.find_next('table', class_='summary_table')
                raw_sev, raw_conf, host, path = "INFO", "Firm", "", ""

                if st:
                    for tr in st.find_all('tr'):
                        row_txt = " ".join([td.get_text().strip() for td in tr.find_all('td')])
                        if "Severity:" in row_txt:
                            raw_sev = row_txt.split("Severity:")[-1].strip()
                        elif "Confidence:" in row_txt:
                            raw_conf = row_txt.split("Confidence:")[-1].strip()
                        elif "Host:" in row_txt:
                            host = row_txt.split("Host:")[-1].strip()
                        elif "Path:" in row_txt:
                            path = row_txt.split("Path:")[-1].strip()

                sev_upper = raw_sev.strip().upper()
                if "HIGH" in sev_upper:
                    severity = "HIGH"
                elif "MED" in sev_upper:
                    severity = "MEDIUM"
                elif "LOW" in sev_upper:
                    severity = "LOW"
                else:
                    severity = "INFO"

                score, cvss_vector = self._calculate_score_and_vector(cat_title, raw_sev, raw_conf)
                if score >= 9.0: severity = "CRITICAL"
                elif score >= 7.0: severity = "HIGH"
                elif score >= 4.0: severity = "MEDIUM"
                elif score > 0.0: severity = "LOW"
                else: severity = "INFO"

                # Extract issue detail and request/response snippets
                issue_detail = ""
                remed_detail = ""
                evidence = ""
                next_elem = elem.find_next('span', class_=['BODH1', 'BODH0'])

                for h2 in elem.find_all_next('h2'):
                    if next_elem and h2.sourceline and next_elem.sourceline and h2.sourceline > next_elem.sourceline:
                        break
                    h2_text = h2.get_text().strip().lower()
                    if "issue detail" in h2_text and not issue_detail:
                        next_span = h2.find_next_sibling('span', class_='TEXT')
                        if next_span:
                            issue_detail = next_span.get_text().strip()
                    elif "remediation detail" in h2_text and not remed_detail:
                        next_span = h2.find_next_sibling('span', class_='TEXT')
                        if next_span:
                            remed_detail = next_span.get_text().strip()
                    elif "request" in h2_text or "response" in h2_text:
                        rr_div = h2.find_next_sibling('div', class_='rr_div')
                        if rr_div and len(evidence) < 1500:
                            evidence += f"\n[{h2.get_text().strip()}]\n{rr_div.get_text().strip()[:400]}"

                target_str = f"{host}{path}".strip() if host else (path or "Web Application Endpoint")

                # Clean Title formatting
                if is_b1 and inst_title and inst_title != cat_title:
                    clean_inst = inst_title.replace(host, '').strip()
                    title = f"{cat_title} ({clean_inst})" if clean_inst else f"{cat_title} ({target_str})"
                else:
                    title = cat_title

                full_desc = f"{issue_detail}\n\n[Background]\n{cat_bg}".strip()
                full_remed = f"{remed_detail}\n\n[Remediation]\n{cat_remed}".strip()

                cves = sorted(list(set(re.findall(r'CVE-\d{4}-\d{4,7}', full_desc + evidence, re.IGNORECASE))))

                return Finding(
                    title=title,
                    severity=severity,
                    severity_score=score,
                    cvss_vector=cvss_vector,
                    confidence=raw_conf or "Firm",
                    cve_list=cves,
                    target=target_str,
                    description=full_desc,
                    remediation=full_remed,
                    evidence=evidence.strip() or issue_detail[:500],
                    plugin_id=inst_id or "burp-issue",
                    source_tool="Burp Suite"
                )

            if b1_list:
                for b1 in b1_list:
                    f = process_element(b1, is_b1=True)
                    if f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                        actionable_findings.append(f)
                    else:
                        info_findings.append(f)
            else:
                f = process_element(b0, is_b1=False)
                if f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    actionable_findings.append(f)
                else:
                    info_findings.append(f)

        map_findings_list(actionable_findings)
        map_findings_list(info_findings)

        return actionable_findings, info_findings

    def _parse_xml(self, content: str) -> Tuple[List[Finding], List[Finding]]:
        import base64
        soup = BeautifulSoup(content, _XML_PARSER)
        actionable_findings: List[Finding] = []
        info_findings: List[Finding] = []

        def _get_child_text(parent, tag_pattern):
            node = parent.find(re.compile(rf'^{tag_pattern}$', re.IGNORECASE))
            return node.get_text().strip() if node else ""

        issues = soup.find_all(re.compile(r'^issue$', re.IGNORECASE))
        for issue in issues:
            title = _get_child_text(issue, 'name') or "Burp Suite Finding"
            raw_sev = _get_child_text(issue, 'severity').upper() or "INFO"
            raw_conf = _get_child_text(issue, 'confidence') or "Firm"

            if "HIGH" in raw_sev:
                severity = "HIGH"
            elif "MED" in raw_sev:
                severity = "MEDIUM"
            elif "LOW" in raw_sev:
                severity = "LOW"
            else:
                severity = "INFO"

            score, cvss_vector = self._calculate_score_and_vector(title, raw_sev, raw_conf)

            h_str = _get_child_text(issue, 'host')
            p_str = _get_child_text(issue, 'path')
            loc_str = _get_child_text(issue, 'location')
            target_str = f"{h_str}{p_str} ({loc_str})".strip() if loc_str else f"{h_str}{p_str}".strip()

            desc_detail = _get_child_text(issue, 'issuedetail')
            desc_bg = _get_child_text(issue, 'issuebackground')
            
            if desc_detail and desc_bg:
                full_desc = f"{desc_detail}\n\n[Issue Background]\n{desc_bg}"
            else:
                full_desc = desc_detail or desc_bg

            r_bg_str = _get_child_text(issue, 'remediationbackground')
            r_dt_str = _get_child_text(issue, 'remediationdetail')
            if r_dt_str and r_bg_str:
                full_remed = f"{r_dt_str}\n\n[Remediation Background]\n{r_bg_str}"
            else:
                full_remed = r_dt_str or r_bg_str


            # Parse HTTP Request / Response evidence proof
            evidence = ""
            for rr in issue.find_all(['requestresponse', 'request', 'response']):
                req = rr.find('request') if rr.name == 'requestresponse' else (rr if rr.name == 'request' else None)
                resp = rr.find('response') if rr.name == 'requestresponse' else (rr if rr.name == 'response' else None)
                
                if req:
                    req_text = req.get_text().strip()
                    if req.get('base64') == 'true':
                        try:
                            req_text = base64.b64decode(req_text).decode('utf-8', errors='ignore')
                        except Exception:
                            pass
                    if req_text and "[HTTP Request]" not in evidence:
                        evidence += f"[HTTP Request]\n{req_text[:1200]}\n\n"
                
                if resp:
                    resp_text = resp.get_text().strip()
                    if resp.get('base64') == 'true':
                        try:
                            resp_text = base64.b64decode(resp_text).decode('utf-8', errors='ignore')
                        except Exception:
                            pass
                    if resp_text and "[HTTP Response]" not in evidence:
                        evidence += f"[HTTP Response Snippet]\n{resp_text[:1200]}\n\n"

            cves = sorted(list(set(re.findall(r'CVE-\d{4}-\d{4,7}', full_desc + evidence, re.IGNORECASE))))

            type_elem = issue.find('type')
            plugin_id = type_elem.get_text().strip() if type_elem else "burp-issue"

            finding = Finding(
                title=title,
                severity=severity,
                severity_score=score,
                cvss_vector=cvss_vector,
                confidence=raw_conf,
                cve_list=cves,
                target=target_str or "Web Application Endpoint",
                description=full_desc,
                remediation=full_remed,
                evidence=evidence.strip() or desc_detail[:500],
                plugin_id=plugin_id,
                source_tool="Burp Suite"
            )

            if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                actionable_findings.append(finding)
            else:
                info_findings.append(finding)

        map_findings_list(actionable_findings)
        map_findings_list(info_findings)

        return actionable_findings, info_findings

    def _parse_plaintext(self, content: str) -> Tuple[List[Finding], List[Finding]]:
        """
        Parses text extracted from Burp Suite PDF reports or plain-text exports.
        Handles both numbered category hierarchy (e.g. '1. SQL injection' -> '1.1. https://...')
        and unnumbered/tabular Burp report formats.
        """
        actionable_findings: List[Finding] = []
        info_findings: List[Finding] = []

        if not content or not content.strip():
            return actionable_findings, info_findings

        # ── 1. Build category map for numbered hierarchies ───────────────────────
        # e.g., '1' -> 'SQL injection', '2' -> 'XML external entity injection'
        cat_map = {}
        # The title class previously omitted "/", so a title was silently cut at the
        # first slash: "2. SSL/TLS CBC Cipher Suites Enabled (Lucky13)" in a real
        # Nessus text export became the finding title "SSL" -- three characters,
        # published as-is into the customer's VAPT report. Slashes, dots, commas,
        # apostrophes, ampersands, plus signs and brackets all occur in real scanner
        # titles ("SSL/TLS", "TLS v1.2", "Cross-Site Scripting [DOM-based]").
        # Newlines stay excluded via the split('\n')[0] below, which already trims
        # the capture to its first line.
        for m in re.finditer(r'(?:^|\n)\s*(?P<num>\d+)\.\s+(?P<title>[A-Za-z0-9_\-\s\(\)/.,\'&+\[\]]+)', content):
            n = m.group('num')
            t = m.group('title').strip()
            if len(t) > 2 and not t.lower().startswith(('http', 'page', 'summary')):
                first_line = t.split('\n')[0].strip()
                first_line = re.sub(r'\s*(Previous|Next|Summary).*$', '', first_line, flags=re.IGNORECASE).strip()
                if first_line:
                    cat_map[n] = first_line

        # ── 2. Find all findings by Severity markers ─────────────────────────────
        sev_matches = list(re.finditer(r'\b(?:Severity|Risk|Risk\s*Level|Rating|Threat\s*Level)\s*[:\-]\s*(?P<sev>Critical|High|Medium|Low|Information|Info)', content, re.IGNORECASE))

        CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

        # Where each issue and instance sits, so a finding is named after the
        # section it is actually in (see _burp_sections).
        _issues, _instances = _burp_sections(content)
        _issue_bounds = []
        for k, (start, num, ttl) in enumerate(_issues):
            end = _issues[k + 1][0] if k + 1 < len(_issues) else len(content)
            first_inst = min((s for s, n, _u in _instances if n == num and start < s < end),
                             default=end)
            _issue_bounds.append((start, end, first_inst, num, ttl))

        def _section_of(pos):
            for start, end, first_inst, num, ttl in _issue_bounds:
                if start <= pos < end:
                    return start, end, first_inst, num, ttl
            return None

        def _instance_of(pos, sec):
            start, end, _fi, num, _t = sec
            hits = [(s, u) for s, n, u in _instances if n == num and start <= s <= pos < end]
            return hits[-1][1] if hits else None

        if sev_matches:
            for i, sm in enumerate(sev_matches):
                next_start = sev_matches[i+1].start() if i+1 < len(sev_matches) else len(content)
                lookback_start = max(0, sm.start() - 600)

                pre_text = content[lookback_start:sm.start()]
                body_text = content[sm.start():next_start]
                full_block = pre_text + '\n' + body_text

                # Instance URL & Category determination
                m_inst = list(re.finditer(r'(?:^|\n)\s*(?:(?P<cat_num>\d+)\.(?P<sub_num>\d+)\.\s+)?(?P<url>https?://[^\s\n]+|\/[^\s\n]+)(?:\s*\[(?P<param>.*?)\])?', pre_text))

                title = "VAPT Finding"
                target = "Web Application Endpoint"

                # Check for explicit Issue / Vulnerability title
                m_vuln = re.search(r'(?:Issue|Vulnerability|Finding|Title)\s*[:\-]\s*([^\n\r<]{3,100})', full_block, re.IGNORECASE)
                if m_vuln:
                    title = m_vuln.group(1).strip()

                if m_inst:
                    last_inst = m_inst[-1]
                    url = last_inst.group('url') or ''
                    param = last_inst.group('param') or ''
                    cat_num = last_inst.group('cat_num') or ''
                    target = f"{url} [{param}]" if param else url
                    cat_title = cat_map.get(cat_num, '')
                    if title == "VAPT Finding":
                        if cat_title:
                            title = f"{cat_title} ({target})" if target else cat_title
                        else:
                            title = target
                else:
                    # Check for standalone category before this
                    m_cat = list(re.finditer(r'(?:^|\n)\s*(?P<cat_num>\d+)\.\s+(?P<cat>[A-Za-z0-9_\-\s\(\)]+)', pre_text))
                    if m_cat and title == "VAPT Finding":
                        cat_num = m_cat[-1].group('cat_num')
                        title = cat_map.get(cat_num, m_cat[-1].group('cat').strip())

                # The section this severity line physically sits in overrides
                # the guesses above, which read the previous issue's text.
                _sec = _section_of(sm.start())
                if _sec is not None:
                    _inst = _instance_of(sm.start(), _sec)
                    if _inst:
                        target = _inst
                        title = f"{_sec[4]} ({_inst})"
                    else:
                        title = _sec[4]
                        # No instance heading: the URL found by the lookback
                        # belonged to the previous issue. Let this finding's
                        # own Host and Path lines below supply the target.
                        target = 'Web Application Endpoint'

                # Severity & Confidence
                raw_sev = sm.group('sev').upper()
                conf_m = re.search(r'Confidence\s*[:\-]\s*(Certain|Firm|Tentative)', body_text, re.IGNORECASE)
                raw_conf = conf_m.group(1) if conf_m else 'Firm'

                # Host & Path
                host_m = re.search(r'Host\s*[:\-]\s*(https?://[^\s\n]+)', body_text, re.IGNORECASE)
                path_m = re.search(r'Path\s*[:\-]\s*([^\s\n]+)', body_text, re.IGNORECASE)
                if host_m:
                    h = host_m.group(1).strip()
                    p = path_m.group(1).strip() if path_m else ''
                    if target == 'Web Application Endpoint':
                        target = f"{h}{p}"

                if "CRITICAL" in raw_sev: severity = "CRITICAL"
                elif "HIGH" in raw_sev: severity = "HIGH"
                elif "MED" in raw_sev: severity = "MEDIUM"
                elif "LOW" in raw_sev: severity = "LOW"
                else: severity = "INFO"

                score, cvss_vector = self._calculate_score_and_vector(title, raw_sev, raw_conf)
                # The report's severity stands. This used to be recomputed from
                # the estimated score, so a finding Burp rated High came out
                # Critical and one it rated Low came out Medium -- the tool
                # contradicting the evidence it was reading, on a customer's
                # report. Burp gives no CVSS; the score is an estimate for the
                # vulnerability class, kept inside the band the report's own
                # severity names so the two can never disagree.
                score = _clamp_to_band(score, severity)

                # Extract Issue detail section.
                #
                # Every terminator here used to require a leading newline ("\nIssue
                # background", "\nReferences"). PDF text extraction does not preserve
                # the source document's line breaks, so on a printed-to-PDF Burp report
                # none of them could ever match -- and with DOTALL the lazy group then
                # ran to the end of body_text, which spans up to the NEXT severity
                # marker. A single description absorbed the raw HTTP request, the full
                # response headers, the Collaborator interaction dump and the heading
                # of the following finding. Confirmed on a delivered customer report.
                #
                # The newline requirement is dropped and the request/response and
                # next-numbered-heading markers are added, so the section ends where it
                # actually ends in both line-preserved and flattened text.
                desc = ""
                m_desc = re.search(
                    _ISSUE_DETAIL_RE, body_text, re.DOTALL | re.IGNORECASE
                )
                if m_desc:
                    desc = m_desc.group(1).strip()
                if not desc:
                    m_bg = re.search(
                        _ISSUE_BACKGROUND_RE, body_text, re.DOTALL | re.IGNORECASE
                    )
                    desc = m_bg.group(1).strip() if m_bg else body_text[:500]
                # Backstop: if every terminator still misses on some unseen export
                # shape, degrade to a truncated description rather than emitting the
                # whole block. A description is a summary field; nothing legitimate
                # needs 20KB of it.
                if len(desc) > _MAX_DESC_CHARS:
                    desc = desc[:_MAX_DESC_CHARS].rstrip() + " […]"

                # Extract Remediation
                remed = ""
                m_remed = re.search(
                    r'Issue remediation\s*\n(.*?)(?=\nReferences|\nVulnerability classifications|$)',
                    body_text, re.DOTALL | re.IGNORECASE
                )
                if m_remed:
                    remed = m_remed.group(1).strip()

                # An instance carries only its own detail; the remediation and
                # the CWE classifications belong to its issue's section, above
                # the first instance. Read them from there.
                _cwes = []
                if _sec is not None:
                    _parent = content[_sec[0]:_sec[2]]
                    if not remed:
                        _mr = _BURP_REMEDIATION_RE.search(_parent)
                        if _mr:
                            remed = _mr.group(1).strip()
                    _mc = _BURP_CLASSIFICATIONS_RE.search(_parent)
                    if _mc:
                        _cwes = ["CWE-" + n for n in _CWE_RE.findall(_mc.group(1))]

                # Evidence: Request / Response snippets
                evidence = ""
                m_req = re.search(r'(?:HTTP )?[Rr]equest\s*\n(.*?)(?=\n(?:HTTP )?[Rr]esponse|\nIssue|$)', body_text, re.DOTALL)
                m_res = re.search(r'(?:HTTP )?[Rr]esponse\s*\n(.*?)(?=\nIssue|\nReferences|$)', body_text, re.DOTALL)
                if m_req:
                    evidence += f"[HTTP Request]\n{m_req.group(1).strip()[:800]}\n\n"
                if m_res:
                    evidence += f"[HTTP Response]\n{m_res.group(1).strip()[:800]}"

                # CVEs from this finding's own section, not the 600-character
                # lookback, which reaches into the previous issue.
                _cve_scope = content[_sec[0]:_sec[1]] if _sec is not None else full_block
                cves = sorted(set(c.upper() for c in CVE_RE.findall(_cve_scope)))
                cves += [c for c in dict.fromkeys(_cwes) if c not in cves]

                finding = Finding(
                    title=title,
                    severity=severity,
                    severity_score=score,
                    cvss_vector=cvss_vector,
                    confidence=raw_conf,
                    cve_list=cves,
                    target=target,
                    description=desc,
                    remediation=remed,
                    evidence=evidence.strip() or desc[:500],
                    plugin_id="burp-pdf",
                    source_tool="Burp Suite",
                )

                if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    actionable_findings.append(finding)
                else:
                    info_findings.append(finding)

        if not actionable_findings and not info_findings:
            # Fallback for OCR / PoC Screenshot text (e.g. shot_burp_sqli.png, shot_burp_xss.png)
            poc_hits = list(re.finditer(r'(?:Vulnerability\s*Proof|Proof\s*of\s*Concept|SQL\s*Injection|Stored\s*XSS|Reflected\s*XSS|Cross-Site\s*Scripting|XSS)[A-Z]*[^\n\r<]{0,60}', content, re.IGNORECASE))
            for ph in poc_hits:
                if _is_non_finding_poc(ph.group(0)):
                    print(
                        f"[VAPT PARSER] Skipped PoC match -- reads as remediation/advice, "
                        f"not a live finding: {ph.group(0).strip()[:80]!r}",
                        flush=True
                    )
                    continue
                match_str = _clean_poc_title(ph.group(0))
                if not match_str:
                    continue
                _cls_name, _cls_desc, _cls_remed, _cls_steps = _describe_poc(match_str)
                # The class name, when it was recognised, rather than the OCR's
                # rendering of it -- "Stored XSS]" arrives as "XSSI", and that
                # string was going into the customer's report and into the
                # keyword tables that derive CIA impact from it.
                _title = f"Visual PoC: {_cls_name or match_str}"
                if _cls_desc:
                    _description = (
                        f"{_cls_desc} Identified from a proof-of-concept "
                        f"screenshot; the captured request and response are "
                        f"reproduced below. Confirm against the live target "
                        f"before reporting."
                    )
                else:
                    # Nothing recognisable: say what is actually known rather
                    # than dressing the matched text up as a description.
                    _description = (
                        f"A proof-of-concept screenshot was supplied showing "
                        f"{match_str}. The vulnerability class could not be "
                        f"determined automatically -- review the captured "
                        f"evidence below and classify this finding."
                    )
                f_poc = Finding(
                    title=_title,
                    severity="HIGH",
                    severity_score=7.5,
                    target="Web Application Endpoint",
                    description=_description,
                    evidence=content[:800],
                    source_tool="Burp Suite / Visual OCR"
                )
                # The fix for THIS class of flaw. Left unset, control_mapper
                # fills in its generic VAPT template, which told the reader to
                # run another scan and to apply a vendor patch -- advice that
                # does not apply to a flaw in the customer's own application.
                if _cls_remed:
                    f_poc.remediation = _cls_remed
                    f_poc.remediation_actionable = _cls_steps
                actionable_findings.append(f_poc)

        map_findings_list(actionable_findings)
        map_findings_list(info_findings)
        return actionable_findings, info_findings

