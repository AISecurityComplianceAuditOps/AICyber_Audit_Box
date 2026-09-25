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
