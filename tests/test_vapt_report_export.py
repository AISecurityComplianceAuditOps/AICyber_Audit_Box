# -*- coding: utf-8 -*-
"""The VAPT report says what the scanners said, and nothing they did not.

Each test pins a point from a client's review of a delivered PortSwigger (Burp)
report: the uploaded file name as the target, scanner names guessed from
keywords, "Internal Network Network VAPT" on a public web application, testing
dates of 20-June-2026 to today, an "XYZ Security Services" footer under a
Dhiware cover, a flat CVSS 8.0 on every High, "N/A - Vendor Security Advisory /
End-of-Life Notice" in place of a CWE, "apply vendor security patches" where
the scanner gave no fix, all informational findings dropped, and four DNS
interaction findings deleted as duplicates of the HTTP ones.
"""
import io
from types import SimpleNamespace

import pytest

from src.core.parsers.finding_schema import Finding
from src.core import report_exporter as rx


# ── dedup: a CWE is a class, not an identity ─────────────────────────────────

def test_different_issues_sharing_cwes_on_one_url_are_not_duplicates():
    http = Finding(title="External service interaction (HTTP)", severity="HIGH", source_tool="Burp Suite",
                   cve_list=["CWE-918", "CWE-406"], target="https://shop.test/catalog [Referer HTTP header]",
                   plugin_id="5.1")
    dns = Finding(title="External service interaction (DNS)", severity="INFO", source_tool="Burp Suite",
                  cve_list=["CWE-918", "CWE-406"], target="https://shop.test/catalog [Referer HTTP header]",
                  plugin_id="11.1")
    assert http.dedup_key() != dns.dedup_key()


def test_two_burp_instances_at_one_url_are_not_duplicates():
    a = Finding(title="Open redirection (DOM-based)", severity="LOW", source_tool="Burp Suite",
                cve_list=["CWE-601"], target="https://shop.test/catalog/product", plugin_id="7.1")
    b = Finding(title="Open redirection (DOM-based)", severity="LOW", source_tool="Burp Suite",
                cve_list=["CWE-601"], target="https://shop.test/catalog/product", plugin_id="7.2")
    assert a.dedup_key() != b.dedup_key()


def test_one_cve_on_one_host_is_still_one_finding():
    a = Finding(title="SWEET32", severity="MEDIUM", cve_list=["CVE-2016-2183", "CWE-327"], target="10.0.0.5:443")
    b = Finding(title="SSL Medium Strength Ciphers", severity="MEDIUM", cve_list=["CVE-2016-2183"], target="10.0.0.5:443")
    assert a.dedup_key() == b.dedup_key()


# ── what the export endpoint hands the exporter ──────────────────────────────

def _row(**kw):
    base = dict(evidence_snippet="", source_files="portswigger_net.pdf", severity_score=0.0,
                target=None, source_tool=None, confidence=None, cvss_vector=None, cve_refs=None)
    base.update(kw)
    return SimpleNamespace(**base)


def test_export_fields_come_from_the_saved_scanner_facts():
    from src.api.endpoints.audit import _vapt_scanner_fields
    got = _vapt_scanner_fields(_row(target="https://shop.test/catalog/filter [category parameter]",
                                    source_tool="Burp Suite", confidence="Tentative",
                                    cve_refs="CWE-89, CWE-94"))
    assert got["target"] == "https://shop.test/catalog/filter [category parameter]"
    assert got["source_tool"] == "Burp Suite" and got["confidence"] == "Tentative"
    assert got["cve_list"] == ["CWE-89", "CWE-94"]
    assert got["severity_score"] is None                  # none assigned, none invented


def test_rows_saved_before_the_columns_read_the_proof_block():
    from src.api.endpoints.audit import _vapt_scanner_fields
    block = ("Target Host: https://shop.test/catalog/product/stock\nPlugin ID:   burp-pdf\n"
             "CVE(s):      CWE-611\nScanner:     Burp Suite\nPlugin Output:\n...")
    got = _vapt_scanner_fields(_row(evidence_snippet=block))
    assert got["target"] == "https://shop.test/catalog/product/stock"   # not the file name
    assert got["source_tool"] == "Burp Suite"
    assert got["cve_list"] == ["CWE-611"]


def test_a_real_scanner_score_is_kept():
    from src.api.endpoints.audit import _vapt_scanner_fields
    assert _vapt_scanner_fields(_row(severity_score=7.5))["severity_score"] == 7.5


# ── exporter helpers ─────────────────────────────────────────────────────────

def test_scope_is_what_was_tested_and_never_invents_internal():
    web = [{"source_tool": "Burp Suite", "target": "https://shop.test/"}]
    label, title = rx._vapt_scope(web, "VAPT")
    assert label == "Web Application" and "Internal" not in title and "Network Network" not in title
    both = web + [{"source_tool": "Nessus", "target": "10.0.0.5:443/tcp"}]
    assert rx._vapt_scope(both, "VAPT")[0] == "Network and Web Application"
    assert rx._vapt_scope(web, "External web assessment")[0] == "External Web Application"


def test_owasp_follows_the_findings_cwe_like_the_risk_category():
    f = {"cve_list": ["CWE-611"], "category": "Security Misconfiguration"}
    assert rx._vapt_owasp(f, "XML external entity injection", "").startswith("A05")


def test_no_remediation_is_never_turned_into_apply_vendor_patches():
    for f in ({"severity": "INFO", "remediation": ""},
              {"severity": "HIGH", "remediation": "", "remediation_actionable": ""},
              {"severity": "HIGH", "remediation": "", "remediation_actionable": "Encode output."}):
        assert "vendor" not in rx._vapt_remediation(f).lower()
    assert rx._vapt_remediation({"remediation": "", "remediation_actionable": "Encode output."}) == "Encode output."


def test_scanner_name_is_never_guessed():
    assert rx._vapt_scanner({"source_tool": "Burp Suite"}) == "Burp Suite"
    assert rx._vapt_scanner({"title": "CVE-2021-44228 SQL injection over TLS"}) == "Not recorded"


# ── the rendered report ──────────────────────────────────────────────────────

def _pdf_text(findings, **meta):
    pytest.importorskip("fpdf")
    from pypdf import PdfReader
    pdf = rx._export_vapt_pdf("VAPT", findings, [], "Completed",
                              metadata={"brand_firm": "Dhiware Technologies Pvt Ltd", **meta})
    return "\n".join((p.extract_text() or "") for p in PdfReader(io.BytesIO(pdf)).pages)


FINDINGS = [
    {"title": "SQL injection (https://shop.test/catalog/product/stock [request body])", "severity": "HIGH",
     "severity_score": None, "confidence": "Tentative", "source_tool": "Burp Suite",
     "target": "https://shop.test/catalog/product/stock [request body]", "cve_list": ["CWE-89"],
     "category": "Injection", "description": "The request body appears to be vulnerable to SQL injection.",
     "remediation": "Use parameterized queries.", "status": "Non-Compliant",
     "evidence_snippet": "Target Host: https://shop.test/catalog/product/stock\nScanner:     Burp Suite"},
    {"title": "Birthday attacks against TLS ciphers with 64bit block size vulnerability (Sweet32)",
     "severity": "MEDIUM", "severity_score": 7.5, "source_tool": "Qualys", "target": "10.0.0.5 / web01:443",
     "cve_list": ["CVE-2016-2183"], "category": "Cryptographic Failures",
     "description": "Legacy block ciphers are vulnerable.", "remediation": "Disable 64-bit block ciphers.",
     "status": "Non-Compliant"},
    {"title": "External service interaction (DNS) (https://shop.test/catalog [Referer HTTP header])",
     "severity": "INFO", "severity_score": None, "source_tool": "Burp Suite", "confidence": "Certain",
     "target": "https://shop.test/catalog [Referer HTTP header]", "cve_list": ["CWE-918"],
     "description": "A DNS lookup was made.", "remediation": "", "status": "Informational"},
]


def test_rendered_report_carries_the_scanners_facts():
    text = _pdf_text(FINDINGS, brand_audit_dates="01-Oct-2022 to 14-Oct-2022")
    assert "Network Network" not in text and "Internal Network" not in text
    assert "XYZ Security Services" not in text
    assert "20-June-2026" not in text and "01-Oct-2022 to 14-Oct-2022" in text
    assert "Vendor Security Advisory" not in text and "vendor security patches" not in text
    assert "Automated VAPT Scanner" not in text
    assert "No CVSS score assigned by Burp Suite" in text
    assert "Detected (Tentative)" in text
    assert "https://shop.test/catalog/product/stock [request body]" in text
    assert "External service interaction (DNS)" in text          # informational kept


def test_a_score_does_not_override_the_scanners_severity():
    """Qualys rates Sweet32 Medium with CVSS 7.5; the report printed HIGH."""
    import re
    text = _pdf_text(FINDINGS)
    assert re.search(r"MEDIUM\s+-\s+CVSS 7\.5", text), "finding card"
    assert re.search(r"7\.5\s+MEDIUM", text), "summary table"
    assert not re.search(r"HIGH\s+-\s+CVSS 7\.5|7\.5\s+HIGH", text)


def test_testing_dates_are_not_invented():
    assert "Testing Dates Not specified" in _pdf_text(FINDINGS[:1])
