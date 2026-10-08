# -*- coding: utf-8 -*-
"""What a mentor reading a delivered VAPT report found broken, and its fixes.

  * 2.2 Scope targets split each target at every space: Burp's
    "https://shop/catalog [Referer HTTP header]" became the cells "[Referer",
    "HTTP" and "header]", sorted in among the real targets.
  * A proof block read "CVE(s): CWE-89, CWE-94" under "CVE References: None
    assigned": the worker listed every reference as a CVE.
  * The contents gave estimated pages (0.65 of a page per finding): a Burp
    report printed "4 Appendix ... 37" for an appendix on page 86.
  * The "3 TECHNICAL DETAIL REPORT: NETWORK AND WEB APPLICATION ..." banner
    was one cell, cut off at the page edge.
  * The Word report's 2.1 gave the session's name as the target assets, and
    its section 3 heading said NETWORK on a web-application report.
"""
import io
import re

from src.core import report_exporter as rx

BURP_TARGETS = [
    "https://shop.test/catalog [Referer HTTP header]",
    "https://shop.test/catalog/search/2 [term parameter]",
    "https://shop.test/catalog/product/stock [request body]",
    "https://shop.test/api/user (/api/user)",
    "10.20.30.40:443/tcp (www)",
    "https://[2001:db8::1]/admin",
    "a.shop.test, b.shop.test",
    "https://shop.test/x [cut short",
]


def _finding(i, target, **kw):
    f = {"control_id": f"VAPT-{i}", "title": f"Finding {i}", "severity": "HIGH", "status": "Non-Compliant",
         "final_result": "NON_COMPLIANT", "source_tool": "Burp Suite", "target": target,
         "description": "The application is vulnerable.", "recommendation": "Fix the input handling.",
         "evidence_snippet": (f"Target Host: {target}\nPlugin ID:   {i}\nCVE(s):      CWE-89, CWE-94\n"
                              "Scanner:     Burp Suite\nPlugin Output:\n" + "GET /x HTTP/1.1\nHost: shop.test\n" * 40)}
    f.update(kw)
    return f


def _findings():
    fs = [_finding(i, t) for i, t in enumerate(BURP_TARGETS[:4], 1)]
    fs.append(_finding(5, "10.20.30.40:443/tcp (www)", source_tool="Nessus", severity="MEDIUM",
                       evidence_snippet="Target Host: 10.20.30.40:443/tcp (www)\nCVE(s):      CVE-2016-2183, CWE-327\n"
                                        "Scanner:     Nessus\nPlugin Output:\nDES-CBC3-SHA"))
    return fs


# -- the helpers --------------------------------------------------------------

def test_scope_targets_are_the_hosts_and_urls_without_the_scanners_notes():
    got = rx._vapt_scope_targets([{"target": t} for t in BURP_TARGETS])
    assert got == sorted({
        "https://shop.test/catalog", "https://shop.test/catalog/search/2",
        "https://shop.test/catalog/product/stock", "https://shop.test/api/user",
        "10.20.30.40:443/tcp", "https://[2001:db8::1]/admin", "a.shop.test", "b.shop.test",
        "https://shop.test/x"})
    assert not [t for t in got if t[0] in "[(" or t[-1] in "])"]


def test_the_cve_line_holds_cves_and_cwes_get_their_own():
    assert rx._vapt_poc_ids("Scanner: x\nCVE(s):      CWE-89, CWE-94\nPlugin Output:") == \
        "Scanner: x\nCWE(s):      CWE-89, CWE-94\nPlugin Output:"
    assert rx._vapt_poc_ids("CVE(s):      CVE-2016-2183, CWE-327") == \
        "CVE(s):      CVE-2016-2183\nCWE(s):      CWE-327"
    assert rx._vapt_poc_ids("CVE(s):      CVE-2016-2183") == "CVE(s):      CVE-2016-2183"


# -- the PDF ------------------------------------------------------------------

def _pdf_pages():
    from pypdf import PdfReader
    out = rx.export_pdf_report("layout check", _findings(), [], "FINAL", audit_type="vapt")
    return [" ".join((p.extract_text() or "").split()) for p in PdfReader(io.BytesIO(out)).pages]


def test_the_contents_give_the_pages_the_sections_are_on():
    pages = _pdf_pages()
    toc = next(p for p in pages if "TABLE OF CONTENTS" in p)
    checked = 0
    for title, banner in (("4 Appendix", "4 APPENDIX"), ("5 Disclaimer", "5 DISCLAIMER"),
                          ("2 Executive Summary", "2 EXECUTIVE SUMMARY"), ("3.3 Findings", "3.3 Findings FN-01")):
        listed = int(re.search(re.escape(title) + r" (\d+)", toc).group(1))
        actual = next(i for i, p in enumerate(pages, 1) if banner in p and "TABLE OF CONTENTS" not in p)
        assert listed == actual, (title, listed, actual)
        checked += 1
    assert checked == 4
    assert len(pages) > 12        # long proofs: the estimate would have been wrong


def test_the_scope_table_has_no_note_fragments():
    page = next(p for p in _pdf_pages() if "2.2 Analysis Overview" in p and "TABLE OF CONTENTS" not in p)
    scope = page[page.index("Scope targets:"):page.index("Assessment Date")]
    for frag in ("[Referer", "header]", "parameter]", "[request", "(www)", "(/api/user)"):
        assert frag not in scope, frag
    assert "https://shop.test/catalog/product/stock" in scope and "10.20.30.40:443/tcp" in scope


def test_the_long_section_banner_is_not_cut_off():
    text = " ".join(_pdf_pages())
    assert ("3 TECHNICAL DETAIL REPORT: NETWORK AND WEB APPLICATION VULNERABILITY ASSESSMENT "
            "AND PENETRATION TESTING") in text


def test_the_proof_block_lists_cwes_as_cwes():
    text = "\n".join(_pdf_pages())
    assert "CVE(s): CWE-" not in text
    assert "CWE(s): CWE-89, CWE-94" in text
    assert "CVE(s): CVE-2016-2183" in text and "CWE(s): CWE-327" in text


# -- the Word report ----------------------------------------------------------

def test_the_word_report_names_the_targets_and_what_was_tested():
    from docx import Document
    d = Document(io.BytesIO(rx.export_docx_report("VAPT - 08 Oct 2026", _findings(), [], "FINAL",
                                                   audit_type="vapt")))
    paras = [p.text for p in d.paragraphs]
    scope = next(p for p in paras if "Target assets:" in p)
    assert "VAPT - 08 Oct 2026" not in scope
    assert "https://shop.test/api/user" in scope and "[Referer" not in scope
    assert "3 TECHNICAL DETAIL REPORT: NETWORK AND WEB APPLICATION VULNERABILITY ASSESSMENT" in paras
    assert not [p for p in paras if p.startswith("CVE(s):") and "CWE-" in p]
