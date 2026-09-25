# -*- coding: utf-8 -*-
"""Every field of a VAPT finding must say what the source report says.

    pytest tests/test_vapt_report_accuracy.py -v

WHY THIS EXISTS

Three real reports were run through the worker's own path and each finding was
checked field by field against the document. None of these showed up as an
error; every one was a confident, wrong statement on a customer's report:

  A human-written pentest report listing its tools ("3. Burp Suite, Licenced")
  was claimed by the Burp parser, which accepts any text containing the words
  "burp suite". Its six findings became one, titled "VAPT Finding".

  The same report's findings table extracted with titles cut to one word and a
  CVSS of 17.0 -- read from the IP address in the next column.

  A Burp Scanner PDF: five findings titled with another issue's URL (XML
  external entity injection published as "/catalog/search/2 [term parameter]"),
  five severities overwritten by the tool's own estimate (SQL injection, rated
  High by Burp, published as Critical; open redirection Low -> Medium), 34 of 35
  findings with no CWE and 25 of 35 with no remediation -- though the report
  states both for every issue.

  Developer guidance of "apply the vendor-supplied patch addressing CWE-601"
  for an open redirect in the application's own code; a "TLS cookie without
  secure flag set" told to change TLS protocol versions.

  A vulnerable JavaScript library filed under Injection because the CVE it
  quotes describes an XSS bug.

  An OCR'd table whose recommendation read "configure the Properly hash" where
  the report says "Properly configure the hash".

The fixtures below are synthetic: they reproduce each document's STRUCTURE,
not its contents. Client reports are never committed.
"""
import io

import pytest

from src.core.parsers import parse_tool_file
from src.core.parsers.burp_parser import BurpParser
from src.core.parsers.control_mapper import (get_actionable_remediation,
                                             map_finding_to_risk_category)
from src.core.parsers.doc_parsers import (_join_cell_lines, _split_line_into_cells,
                                          extract_pdf_table_rows)
from src.core.parsers.finding_schema import Finding
from src.core.parsers.pentest_report_parser import PDF_TABLES_MARKER, PentestReportParser


def _all(name, text):
    actionable, info = parse_tool_file(name, text, framework="vapt")
    return actionable + (info if isinstance(info, list) else [])


# ── a report that names its tools is not a Burp export ───────────────────────

HUMAN_REPORT = """Penetration Testing Report for Example Services Ltd.
6. Auditing Tools:
S. No  Name of Tool/Software used  Version  Open Source/Licensed
1.  Nmap  V 7.95  Open Source
2.  Kali Linux  V 2025.1a  Open Source
3.  Burp Suite  Licenced
12. Test Summary
S. No | Observation | Severity | Affected IP/URL | CVE/CWE | Final Status
1. | Missing Encryption of Sensitive Data | Low (CVSS Score: 2.0) | https://10.1.2.3:9007 | CWE-311 | Open
"""


def test_mentioning_burp_suite_does_not_make_a_document_a_burp_export():
    assert not BurpParser().can_parse("report.pdf", HUMAN_REPORT)


def test_that_report_yields_its_own_finding_not_an_invented_one():
    titles = [f.title for f in _all("report.pdf", HUMAN_REPORT)]
    assert titles == ["Missing Encryption of Sensitive Data"], titles
    assert "VAPT Finding" not in titles


def test_a_real_burp_export_is_still_recognised():
    assert BurpParser().can_parse("scan.pdf", "Summary\nSeverity: High\nIssue detail\nThe x")
    assert BurpParser().can_parse("scan.xml", "<issues><issue></issue></issues>")


# ── a Burp PDF: title, severity, CWE and remediation from the right section ──

BURP_PDF = """Burp Scanner Sample Report
Contents
1. SQL injection
1.1. https://shop.test/catalog/filter [category parameter]
2. XML external entity injection
3. Open redirection (DOM-based)
1. SQL injection
Next
There are 2 instances of this issue:
/catalog/filter [category parameter]
/catalog/stock [session cookie]
Issue background
SQL injection vulnerabilities arise when user data reaches a query unsafely.
Issue remediation
The most effective way to prevent SQL injection attacks is to use parameterized queries.
References
Web Security Academy: SQL injection
Vulnerability classifications
CWE-89: Improper Neutralization of Special Elements used in an SQL Command
CWE-116: Improper Encoding or Escaping of Output
1.1. https://shop.test/catalog/filter [category parameter]
Next
Summary
Severity: High
Confidence: Firm
Host: https://shop.test
Path: /catalog/filter
Issue detail
The category parameter appears to be vulnerable to SQL injection attacks.
1.2. https://shop.test/catalog/stock [session cookie]
Previous Next
Summary
Severity: High
Confidence: Firm
Host: https://shop.test
Path: /catalog/stock
Issue detail
The session cookie appears to be vulnerable to SQL injection attacks.
2. XML external entity injection
Previous Next
Summary
Severity: High
Confidence: Firm
Host: https://shop.test
Path: /catalog/product/stock
Issue detail
The application is vulnerable to XML external entity injection.
Issue remediation
Parsers that process XML from untrusted sources should disable external resources.
Vulnerability classifications
CWE-611: Improper Restriction of XML External Entity Reference
3. Open redirection (DOM-based)
Previous Next
There are 1 instances of this issue:
/catalog/product
Issue remediation
Do not dynamically set redirection targets using data from an untrusted source.
Vulnerability classifications
CWE-601: URL Redirection to Untrusted Site
3.1. https://shop.test/catalog/product
Previous
Summary
Severity: Low
Confidence: Tentative
Host: https://shop.test
Path: /catalog/product
Issue detail
Data is read from location.search and passed to xhr.open.
"""


def _burp():
    act, info = BurpParser()._parse_plaintext(BURP_PDF)
    return {f.title: f for f in act + info}


def test_each_finding_is_titled_by_the_section_it_sits_in():
    """XXE was published under the previous issue's instance URL."""
    titles = sorted(_burp())
    assert "XML external entity injection" in titles, titles
    assert "SQL injection (https://shop.test/catalog/filter [category parameter])" in titles
    assert "SQL injection (https://shop.test/catalog/stock [session cookie])" in titles
    assert not any(t.startswith("/") for t in titles), titles


def test_a_single_instance_issue_takes_its_own_host_and_path():
    assert _burp()["XML external entity injection"].target == "https://shop.test/catalog/product/stock"


def test_the_reports_severity_is_never_overwritten():
    """Burp rated SQL injection High and open redirection Low; so must we."""
    by = _burp()
    for title, f in by.items():
        if title.startswith("SQL injection"):
            assert f.severity == "HIGH", (title, f.severity)
    assert by["XML external entity injection"].severity == "HIGH"
    redirect = [f for t, f in by.items() if t.startswith("Open redirection")]
    assert redirect and redirect[0].severity == "LOW", [f.severity for f in redirect]


def test_burp_findings_carry_no_invented_cvss():
    """Burp assigns no CVSS. The fixed per-type numbers (SQL injection 9.8,
    anything High 8.0) were printed as if assessed; a client found XSS at 8.0
    beside a vector that computes to 6.1."""
    for title, f in _burp().items():
        assert f.severity_score is None and f.cvss_vector is None, (title, f.severity_score)


def test_burp_findings_are_numbered_as_in_the_report():
    """Two instances of one issue at one URL must stay two findings."""
    ids = [f.plugin_id for f in _burp().values()]
    assert len(ids) == len(set(ids)), ids


def test_every_instance_inherits_its_issues_cwes():
    by = _burp()
    for title, f in by.items():
        if title.startswith("SQL injection"):
            assert "CWE-89" in f.cve_list and "CWE-116" in f.cve_list, (title, f.cve_list)
    assert by["XML external entity injection"].cve_list == ["CWE-611"]


def test_every_instance_inherits_its_issues_remediation():
    """25 of 35 had none: it lives in the issue's section, above the instances."""
    for title, f in _burp().items():
        assert f.remediation.strip(), "%s has no remediation" % title
    sqli = [f for t, f in _burp().items() if t.startswith("SQL injection")]
    assert all("parameterized queries" in f.remediation for f in sqli)


# ── developer guidance: a CWE is not a patch ─────────────────────────────────

def _guidance(title, cve_list, remediation="", description=""):
    return get_actionable_remediation(Finding(
        title=title, severity="LOW", cve_list=list(cve_list),
        remediation=remediation, description=description))


@pytest.mark.parametrize("title,cwe", [
    ("Open redirection (DOM-based)", "CWE-601"),
    ("Client-side prototype pollution", "CWE-1321"),
    ("Cryptographic Failure", "CWE-310"),
    ("Missing Encryption of Sensitive Data", "CWE-311"),
    ("Client-Side Enforcement of Server-Side Security", "CWE-602"),
])
def test_a_weakness_class_is_never_answered_with_a_vendor_patch(title, cwe):
    g = _guidance(title, [cwe])
    assert "vendor-supplied patch" not in g, (title, g)


def test_a_cwe_with_no_guidance_of_its_own_still_is_not_a_vendor_patch():
    """Isolates the CVE/CWE check from the CWE guidance table.

    Mapped CWEs are answered before the fallback is reached, which would hide a
    regression there. CWE-20 has no entry, so this reaches the fallback, where
    the first cve_list entry used to be taken as a patchable CVE.
    """
    g = _guidance("Unusual weakness", ["CWE-20"], remediation="Validate the input.")
    assert "vendor-supplied patch" not in g, g
    assert "Validate the input." in g, g


def test_a_real_cve_still_gets_the_patch_advice_it_needs():
    g = _guidance("Some Outdated Component 1.2", ["CVE-2021-44228"])
    assert "patch" in g.lower()


def test_the_reports_cwe_outranks_a_word_in_the_title():
    """"TLS cookie..." matched the "tls" template and got protocol advice."""
    g = _guidance("TLS cookie without secure flag set", ["CWE-614"])
    assert "Secure" in g and "cookie" in g.lower(), g


def test_open_redirection_is_matched_despite_the_longer_spelling():
    g = _guidance("Open redirection (DOM-based)", [])
    assert "redirect" in g.lower() and "vendor" not in g.lower(), g


# ── category ─────────────────────────────────────────────────────────────────

def _category(title, cve_list, description=""):
    return map_finding_to_risk_category(Finding(
        title=title, severity="LOW", cve_list=list(cve_list), description=description))


def test_a_vulnerable_library_is_not_filed_as_injection_because_its_cve_mentions_xss():
    cat = _category("Vulnerable JavaScript dependency", ["CVE-2020-7676", "CWE-1104"],
                    description="CVE-2020-7676: angular.js allows cross site scripting.")
    assert cat == "Vulnerable Components", cat


def test_the_extracted_cwe_decides_when_the_title_says_nothing():
    """Isolates the CWE-list lookup from the keyword rules.

    A title naming no class, a mapped CWE, and a description that mentions
    another class: only the CWE list can classify it correctly.
    """
    cat = _category("Component issue", ["CWE-1104"],
                    description="The library allows cross site scripting in some calls.")
    assert cat == "Vulnerable Components", cat


@pytest.mark.parametrize("title,cwes", [
    ("Cryptographic Failure", ["CWE-310"]),
    ("Cleartext Transmission of Phone Numbers", ["CWE-319"]),
])
def test_cryptographic_failures_are_filed_as_such(title, cwes):
    assert _category(title, cwes) == "Cryptographic Failures", title


def test_missing_encryption_follows_owasps_own_list():
    # CWE-311 is in OWASP's A04:2021 Insecure Design list, not A02. This test
    # expected Cryptographic Failures while the CWE table lacked CWE-311 and
    # the word "encryption" decided it.
    assert _category("Missing Encryption of Sensitive Data", ["CWE-311"]) == "Insecure Design"


# ── report tables: cells whole, numbers real ─────────────────────────────────

def test_a_url_broken_across_a_cell_wrap_is_rejoined():
    assert _join_cell_lines("https://172.21.13\n1.47:9007") == "https://172.21.131.47:9007"
    assert (_join_cell_lines("https://10.0.0.1:9007/ekycre\ngistration/registe\nrPan.html")
            == "https://10.0.0.1:9007/ekycregistration/registerPan.html")


def test_words_wrapped_in_a_cell_keep_their_space():
    assert _join_cell_lines("Cleartext\nTransmission of\nPhone Numbers") == \
        "Cleartext Transmission of Phone Numbers"
    assert _join_cell_lines("https://10.0.0.1:9007\nPhone Number") == \
        "https://10.0.0.1:9007 Phone Number"


def test_a_cvss_score_above_ten_is_never_published():
    """17.0 was read out of an IP address beside a wrapped severity cell."""
    text = ("VAPT Penetration Testing Report\n"
            "S. No | Observation | Severity | Affected | CVE/CWE\n"
            "1. | Cleartext Transmission | Low (CVSS https://172.21.131.47 | x | CWE-319\n")
    for f in _all("r.pdf", text):
        assert f.severity_score is None or 0 <= f.severity_score <= 10, f.severity_score


def _ruled_table_pdf():
    reportlab = pytest.importorskip("reportlab")
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
    from reportlab.lib import colors
    data = [
        ["S. No", "Observation", "Severity", "Affected\nIP/URL", "CVE/CWE", "Final\nStatus"],
        ["1.", "Cleartext\nTransmission of\nPhone Numbers", "Low (CVSS\nScore: 2.0)",
         "https://172.21.13\n1.47:9007", "CWE-319", "Closed"],
        ["2.", "Missing\nEncryption of\nSensitive Data", "Medium (CVSS\nScore: 4.2)",
         "https://172.21.13\n1.47:9007", "CWE-311", "Open"],
    ]
    buf = io.BytesIO()
    t = Table(data)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.black)]))
    SimpleDocTemplate(buf, pagesize=A4).build([t])
    return buf.getvalue()


def test_a_ruled_pdf_table_comes_back_one_row_per_finding():
    rows = extract_pdf_table_rows(_ruled_table_pdf())
    body = [r for r in rows if r.startswith(("1.", "2."))]
    assert len(body) == 2, rows
    assert "Cleartext Transmission of Phone Numbers" in body[0]
    assert "https://172.21.131.47:9007" in body[0]
    assert "Low (CVSS Score: 2.0)" in body[0]


def test_the_report_parser_reads_those_rows_whole():
    rows = extract_pdf_table_rows(_ruled_table_pdf())
    text = "Penetration Testing Report\n(flowing text)" + PDF_TABLES_MARKER + "\n".join(rows)
    act, info = PentestReportParser().parse("report.pdf", text)
    by = {f.title: f for f in act + info}
    assert "Cleartext Transmission of Phone Numbers" in by, list(by)
    f = by["Missing Encryption of Sensitive Data"]
    assert f.severity == "MEDIUM" and f.severity_score == 4.2
    assert f.target == "https://172.21.131.47:9007"


def test_scanner_parsers_never_see_the_appended_table_rows():
    """Appended to a Burp PDF they would read as part of its last issue."""
    seen = {}
    real = BurpParser.parse

    def spy(self, filename, content):
        seen["content"] = content
        return real(self, filename, content)

    BurpParser.parse = spy
    try:
        parse_tool_file("scan.pdf", "Summary\nSeverity: High\nIssue detail\nX"
                        + PDF_TABLES_MARKER + "1. | Injected Row | High | CWE-1",
                        framework="vapt")
    finally:
        BurpParser.parse = real
    assert "Injected Row" not in seen.get("content", ""), "table rows leaked to Burp"


# ── a combined report: summary table, detail tables, additional-findings table ─
# The shape of a real 131-finding report. Read before as 237 findings: the CVSS
# cell glued to each title ("ASP.NET Core SEoL | 10.0"), no score, no host, no
# remediation, every finding twice, and six findings named "CVSSv3.0 Base
# Metrics | 10.0" made out of the detail tables.

_COMBINED_ROWS = [
    "Sr. No. | Vulnerabilities | CVSS Score | Severity",
    "1. | ASP.NET Core SEoL | 10.0 | CRITICAL",
    "2. | Notepad++ < 8.9.6.1 Multiple Vulnerabilities | 7.8 | HIGH",
    "3. | Security Updates for Microsoft Office Viewers And Compatibility Products (February 2019) | 6.5 | MEDIUM",
    "4. | Windows Speculative Execution Configuration Check - Intel BHI (CVE-2022-0001) | 6.5 | MEDIUM",
    "5. | Windows Speculative Execution Configuration Check | 6.5 | MEDIUM",
    "6. | Strict transport security not enforced | 3.5 | LOW",
    "OVERALL SCORE | 10.0 | CRITICAL",
    "Vulnerability Description | ASP.NET Core SEoL",
    "Target(s) | 13.126.199.93",
    "Status | Detected",
    "CVSSv3.0 Base Metrics | 10.0 CRITICAL Exploitability Metrics: AV: Network, AC: Low",
    "Proof of Concept | Synopsis An unsupported version of ASP.NET Core is installed. "
    "Description Lack of support implies that no new security patches will be released.",
    "Vulnerability Description | ASP.NET Core SEoL",           # repeated after a page break
    "Remediation | Upgrade to a version of ASP.NET Core that is currently supported.",
    "References | OWASP / OSSTMM / NIST Security Recommendations",
    # numbered independently of the summary: #31 here is not summary #31
    "# | Vulnerability | CVSS | Severity | Target",
    "31. | Notepad++ < 8.9.6.1 Multiple Vulnerabilities | 7.8 | HIGH | 13.126.199.93, 3.108.211.52",
    "32. | Security Updates for Microsoft Office Viewers And Compatibility Products (Februa | 6.5 | MEDIUM | 3.108.211.52",
    "33. | Windows Speculative Execution Configuration Check - Intel BHI (CVE-2022-0001) | 6.5 | MEDIUM "
    "| 13.126.199.93, 3.108.211.52",
    "34. | Windows Speculative Execution Configuration Check | 6.5 | MEDIUM | 13.126.199.93",
    "35. | Strict transport security not enforced | 3.5 | LOW | https://ginandjuice.shop/",
]


def _combined():
    text = ("Combined Internal Network & Web Application VAPT Validation Report\n(flowing text)"
            + PDF_TABLES_MARKER + "\n".join(_COMBINED_ROWS))
    return {f.title: f for f in _all("combined.pdf", text)}


def test_each_finding_of_a_combined_report_is_listed_once_under_its_full_name():
    found = _combined()
    assert sorted(found) == sorted([
        "ASP.NET Core SEoL",
        "Notepad++ < 8.9.6.1 Multiple Vulnerabilities",
        "Security Updates for Microsoft Office Viewers And Compatibility Products (February 2019)",
        "Windows Speculative Execution Configuration Check - Intel BHI (CVE-2022-0001)",
        "Windows Speculative Execution Configuration Check",
        "Strict transport security not enforced",
    ]), list(found)


def test_the_cvss_column_is_the_score_not_part_of_the_title():
    found = _combined()
    assert found["ASP.NET Core SEoL"].severity_score == 10.0
    assert found["Strict transport security not enforced"].severity_score == 3.5
    assert (found["Strict transport security not enforced"].severity,
            found["ASP.NET Core SEoL"].severity) == ("LOW", "CRITICAL")


def test_the_additional_table_gives_each_finding_its_hosts():
    found = _combined()
    assert found["Notepad++ < 8.9.6.1 Multiple Vulnerabilities"].target == "13.126.199.93, 3.108.211.52"
    assert found["Security Updates for Microsoft Office Viewers And Compatibility Products "
                 "(February 2019)"].target == "3.108.211.52"
    assert found["Windows Speculative Execution Configuration Check"].target == "13.126.199.93"
    assert (found["Windows Speculative Execution Configuration Check - Intel BHI (CVE-2022-0001)"].target
            == "13.126.199.93, 3.108.211.52")
    assert found["Strict transport security not enforced"].target == "https://ginandjuice.shop/"


def test_a_findings_detail_table_gives_its_host_description_and_remediation():
    f = _combined()["ASP.NET Core SEoL"]
    assert f.target == "13.126.199.93"
    assert f.remediation == "Upgrade to a version of ASP.NET Core that is currently supported."
    assert f.description == ("An unsupported version of ASP.NET Core is installed.\n\n"
                             "Lack of support implies that no new security patches will be released.")


def test_a_version_number_is_not_a_host():
    text = ("VAPT Report\nSr. No. Vulnerabilities CVSS Score Severity\n"
            "1. Notepad++ < 8.9.6.1 Multiple Vulnerabilities 7.8 HIGH\n")
    f, = _all("r.pdf", text)
    assert (f.title, f.target, f.severity_score) == ("Notepad++ < 8.9.6.1 Multiple Vulnerabilities", "", 7.8)


def test_a_number_ending_a_title_stays_in_it_without_a_cvss_column():
    text = "VAPT Report\nS. No Observation Severity Status\n1. Deprecated TLS 1.0 MEDIUM Open\n"
    f, = _all("r.pdf", text)
    assert (f.title, f.severity_score) == ("Deprecated TLS 1.0", None)


def test_a_totals_row_is_not_folded_into_the_last_finding():
    reportlab = pytest.importorskip("reportlab")
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
    t = Table([["Sr. No.", "Vulnerabilities", "CVSS Score", "Severity"],
               ["1.", "Strict transport security not enforced", "3.5", "LOW"],
               ["", "OVERALL SCORE", "10.0", "CRITICAL"]])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.black)]))
    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4).build([t])
    rows = extract_pdf_table_rows(buf.getvalue())
    assert "1. | Strict transport security not enforced | 3.5 | LOW" in rows, rows


# ── OCR: a merged line is cut back into its cells ────────────────────────────

def _word(value, x0, x1):
    return {"value": value, "geometry": ((x0, 0.1), (x1, 0.2))}


def test_a_line_spanning_two_cells_is_split_at_the_cell_gap():
    """Measured: 0.003-0.008 between words of a cell, 0.022-0.030 between cells."""
    line = {"words": [_word("CWE-310", 0.390, 0.460), _word("configure", 0.489, 0.590),
                      _word("the", 0.596, 0.630)]}
    cells = [c[4] for c in _split_line_into_cells(line, 0.1, 0.2)]
    assert cells == ["CWE-310", "configure the"], cells


def test_a_line_whose_words_have_no_position_is_left_whole():
    """This runs on every OCR line; missing geometry must degrade, never raise."""
    line = {"words": [{"value": "a"}, {"value": "b"}],
            "geometry": ((0.1, 0.1), (0.3, 0.2))}
    assert [c[4] for c in _split_line_into_cells(line, 0.1, 0.2)] == ["a b"]


# ── a Word report's tables, read row by row ──────────────────────────────────
# A real report's .docx came out 52 rows right out of 138 with 16 invented
# findings: Red Hat rows rated "Important" dropped, rows sharing a name
# dropped, a risk register cut off at a blank status cell, false positives
# reported as open, and legend rows ("Below 3.9", "Major") published.

def _word_report():
    docx = pytest.importorskip("docx")
    d = docx.Document()
    d.add_paragraph("Vulnerability Assessment and Penetration Test Report")

    def table(rows):
        t = d.add_table(rows=0, cols=len(rows[0]))
        for r in rows:
            cells = t.add_row().cells
            for i, v in enumerate(r):
                cells[i].text = v

    table([["S.No", "CVSS score", "Severity of vulnerability"],     # a legend
           ["1", "9.0 - 10.0", "Critical"], ["4", "Below 3.9", "Low"]])
    table([["CVE Number", "Vulnerability Desc", "RHEL severity", "Fix Release"],
           ["CVE-2021-22543", "RHEL 7 : kernel (RHSA-2021:3801)", "Important", "Quarterly patch fix\n(April)"],
           ["CVE-2021-37576", "RHEL 7 : kernel (RHSA-2021:3801)", "Important", "Quarterly patch fix"],
           ["CVE-2021-3653", "RHEL 7 : kernel (RHSA-2021:3801)", "Moderate", "Quarterly patch fix"]])
    table([["Reference", "CVE", "Vuln Description", "F5 Severity", "Fix Release and Impact"],
           ["INT-86224", "CVE-2016-2183", "SSL Medium Strength Cipher Suites Supported (SWEET32)", "Medium",
            "False Positive. Already strong ciphers are used"],
           ["K54892865", "CVE-2022-23024", "BIG-IP AFM vulnerability", "Medium", "Fixed in 16.1"],
           ["K16101409", "CVE-2022-23028", "BIG-IP AFM vulnerability", "Medium", "Future release"]])
    table([["PR ref", "Subsystem", "Vulnerability Name", "Severity", "Release To FIX"],
           ["INT-84586", "IDAP", "Clear Text Data Transmission", "Medium", "11.4"],
           ["", "Backend F5", "Clear text data transmission", "Medium", "12.1"],
           ["S.No.", "Sub System", "CRITICAL", "HIGH", "Low"]])           # another table's header row
    table([["Risk ID", "Risk", "Severity", "Risk status"],
           ["Product Risk-385", "Mitigation of Pen Test findings of WOC in AWS", "High", ""],
           ["Product Risk-312", "No Reauthentication before changing password", "High", "Done"],
           ["Product Risk-370", "User session tokens not expired after logout", "Medium", "Open"]])
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


def _word_findings():
    from src.core.parsers.doc_parsers import extract_docx_table_rows, extract_text
    data = _word_report()
    f = io.BytesIO(data)
    f.name = "report.docx"
    a, i = parse_tool_file("report.docx", extract_text(f), framework="vapt",
                           table_rows=lambda: extract_docx_table_rows(data))
    return a, (i if isinstance(i, list) else [])


def test_word_tables_are_read_row_by_row_with_every_row_kept():
    a, i = _word_findings()
    got = sorted((f.title, f.severity) for f in a + i)
    assert got == sorted([
        ("RHEL 7 : kernel (RHSA-2021:3801)", "HIGH"), ("RHEL 7 : kernel (RHSA-2021:3801)", "HIGH"),
        ("RHEL 7 : kernel (RHSA-2021:3801)", "MEDIUM"),
        ("SSL Medium Strength Cipher Suites Supported (SWEET32)", "INFO"),
        ("BIG-IP AFM vulnerability", "INFO"), ("BIG-IP AFM vulnerability", "MEDIUM"),
        ("Clear Text Data Transmission", "MEDIUM"), ("Clear text data transmission", "MEDIUM"),
        ("Mitigation of Pen Test findings of WOC in AWS", "HIGH"),
        ("No Reauthentication before changing password", "INFO"),
        ("User session tokens not expired after logout", "MEDIUM"),
    ]), got


def test_rows_sharing_a_name_keep_their_own_cves():
    a, i = _word_findings()
    kernel = sorted(c for f in a + i if f.title.startswith("RHEL 7 : kernel") for c in f.cve_list)
    assert kernel == ["CVE-2021-22543", "CVE-2021-3653", "CVE-2021-37576"]


def test_a_false_positive_is_informational_and_says_so():
    a, i = _word_findings()
    fp = next(f for f in i if "SWEET32" in f.title)
    assert fp.description.startswith("Recorded as a FALSE POSITIVE")
    assert "SWEET32" not in {f.title for f in a}


def test_a_release_column_is_not_remediation():
    a, _i = _word_findings()
    assert all(f.remediation not in ("11.4", "12.1") for f in a), [f.remediation for f in a]


def test_nessus_table_with_no_score_gets_none_and_the_stated_target():
    text = ("WAVE POC - VULNERABILITY & INFRASTRUCTURE REPORT\n"
            "Target Infrastructure: 10.240.0.0/24 | Tools: Nessus, Nmap\n"
            "Plugin ID\nVulnerability Name\nSeverity\nISO Control\n"
            "189421\nOpenSSH 7.2p1 Remote Code Execution (CVE-2024-6387)\nCRITICAL\n8.8 Tech Vuln Mgmt\n"
            "104820\nDeprecated TLS 1.0 Protocol Detection\nMEDIUM\n8.20 Network Security\n")
    got = {f.title: f for f in _all("wave.pdf", text)}
    ssh = got["OpenSSH 7.2p1 Remote Code Execution (CVE-2024-6387)"]
    assert (ssh.severity, ssh.severity_score, ssh.target) == ("CRITICAL", None, "10.240.0.0/24")
    tls = got["Deprecated TLS 1.0 Protocol Detection"]
    assert (tls.severity, tls.severity_score) == ("MEDIUM", None)


def test_a_totals_row_with_every_cell_filled_is_not_a_finding():
    """A Word table writes the totals row with all four cells: "OVERALL |
    OVERALL SCORE | 10.0 | CRITICAL" was published as a CRITICAL finding."""
    text = ("VAPT Report\n(flowing text)" + PDF_TABLES_MARKER +
            "Sr. No. | Vulnerabilities | CVSS Score | Severity\n"
            "1. | Insecure Windows Service Permissions | 8.4 | HIGH\n"
            "OVERALL | OVERALL SCORE | 10.0 | CRITICAL\n")
    assert [f.title for f in _all("r.docx", text)] == ["Insecure Windows Service Permissions"]


# ── a Nessus HTML export organised by host ───────────────────────────────────
# Each host is named once in a "Host Information" table; its plugins follow,
# headed "46313 - Title" (no "(count)"), and their output names only the port.
# All 347 findings of a real export came out with no host, the plugin id glued
# to the title, and an empty plugin id.

def _by_host_section(ip, block_id):
    return f"""
<div class="details-header">Host Information<div class="clear"></div></div>
<div class="table-wrapper details"><table><tbody>
<tr><td>Netbios Name:</td><td>HOST-{block_id}</td></tr>
<tr><td>IP:</td><td>{ip}</td></tr>
</tbody></table></div>
<div class="details-header">Vulnerabilities<div class="clear"></div></div>
<div id="{block_id}" class="" onclick="toggleSection('{block_id}-container');">46313 - MS10-031: Vulnerability in Microsoft Visual Basic for Applications<div id="{block_id}-toggletext"> - </div></div>
<div id="{block_id}-container" class="section-wrapper">
<div class="details-header">Synopsis<div class="clear"></div></div>
<div>Arbitrary code can be executed on the remote host.<div class="clear"></div></div>
<div class="details-header">Description<div class="clear"></div></div>
<div>A stack memory corruption vulnerability exists.<div class="clear"></div></div>
<div class="details-header">Solution<div class="clear"></div></div>
<div>Microsoft has released a set of patches.<div class="clear"></div></div>
<div class="details-header">Risk Factor<div class="clear"></div></div>
<div>High<div class="clear"></div></div>
<div class="details-header">CVSS v3.0 Base Score<div class="clear"></div></div>
<div>9.8 (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)<div class="clear"></div></div>
<div class="details-header">Plugin Output<div class="clear"></div></div>
<h2>tcp/445/cifs</h2>
<div>Vbe6.dll has not been patched.<div class="clear"></div></div>
</div>
"""


def test_a_nessus_by_host_export_gives_each_finding_its_host():
    from src.core.parsers.nessus_parser import NessusParser
    html = ("<html><body><h1>Report generated by Tenable Nessus</h1>"
            + _by_host_section("10.0.0.5", "id7") + _by_host_section("10.0.0.6", "id9")
            + "</body></html>")
    a, i = NessusParser().parse("scan_by_host.html", html)
    got = sorted((f.plugin_id, f.title, f.target, f.severity, f.severity_score) for f in a + i)
    title = "MS10-031: Vulnerability in Microsoft Visual Basic for Applications"
    assert got == [("46313", title, "10.0.0.5", "CRITICAL", 9.8),
                   ("46313", title, "10.0.0.6", "CRITICAL", 9.8)], got
