# -*- coding: utf-8 -*-
"""
Multi-Tool Vulnerability Ingestion Engine (Nessus, Nmap, BurpSuite, Qualys, Trivy, CSV, HTML)
"""
from typing import Any, Callable, List, Optional, Tuple
from .finding_schema import Finding
from .base_parser import BaseParser, is_image_file
from .control_mapper import map_finding_to_control, map_findings_list, map_pqc_findings_list
from .nessus_parser import NessusParser
from .nmap_parser import NmapParser
from .burp_parser import BurpParser
from .qualys_parser import QualysParser
from .trivy_parser import TrivyParser
from .kali_parser import KaliParser
from .zap_parser import ZapParser
from .openvas_parser import OpenVasParser
from .nuclei_parser import NucleiParser
from .tls_scan_parser import TlsScanParser
from .code_scan_parser import CodeScanParser
from .pentest_report_parser import PentestReportParser, PDF_TABLES_MARKER
from .pqc_parser import PQCParser, pqc_extract_text, _PQC_BINARY_EXTENSIONS

ALL_PARSERS = [
    NessusParser(),
    NmapParser(),
    # Before BurpParser, whose detection also accepts "<OWASPZAPReport" -- it
    # claimed ZAP XML reports and read nothing from them.
    ZapParser(),
    BurpParser(),
    # Before QualysParser, whose detection also accepts OpenVAS markers and
    # labelled OpenVAS results "Qualys".
    OpenVasParser(),
    QualysParser(),
    TrivyParser(),
    NucleiParser(),
    TlsScanParser(),
    # Kali console tools (nikto, sqlmap, gobuster, hydra, wpscan). Sits after the
    # structured-export parsers and before PQCParser: its signatures are specific
    # tool banners, so it will not steal a Nessus/Burp/Trivy export, but it must
    # get its chance before PQC's weak 2-keyword check claims the file.
    KaliParser(),
    # Code / dependency scanner exports (SARIF, Grype, npm audit, gitleaks,
    # Bandit) and generic JSON findings lists; after every tool-specific parser.
    CodeScanParser(),
    # A pentest report written by a human, not a scanner export. It goes after
    # every structured-export parser -- a real Nessus or Burp file must be read
    # by its own parser, not scraped as a table -- and before PQCParser, whose
    # two-keyword check would otherwise claim any report mentioning TLS or RSA.
    #
    # Added because the tool returned nothing for the artifact auditors most
    # often hold: the PDF the testing firm delivered. One such report produced
    # zero findings; another produced exactly one, titled "Executive", scraped
    # out of the heading "Executive Summary" by the Burp fallback while its six
    # real vulnerabilities went unreported.
    PentestReportParser(),
    # PQCParser goes LAST -- its can_parse() is a weak-signal (2+ keyword) check
    # like Nessus's own fallback path, so it must never steal a file that a more
    # specific structural-signature parser above would have claimed.
    PQCParser(),
]

_TEXT_FIELDS = ("title", "description", "remediation", "evidence", "remediation_actionable", "target")


def _scrub(findings) -> None:
    """Remove U+FFFD, the replacement character a PDF text extractor leaves for
    a glyph it could not map. It reached a delivered report as "[?]" (Burp's
    "replaced with two backslashes" came out "replaced with two [?]")."""
    for f in findings if isinstance(findings, list) else []:
        for name in _TEXT_FIELDS:
            v = getattr(f, name, None)
            if isinstance(v, str) and "�" in v:
                setattr(f, name, v.replace("[�]", "").replace("�", "").replace("  ", " "))
        # A title is one line. A wrapped cell brought its line break with it
        # ("...64bit block size vulnerability\n(Sweet32)").
        t = getattr(f, "title", None)
        if isinstance(t, str) and ("\n" in t or "\r" in t or "\t" in t):
            f.title = " ".join(t.split())


# Where one tool's console output begins. An auditor's evidence file often holds
# several tools' output pasted one after another; the first parser to claim the
# file read all of it and every other tool's findings were lost (Nmap + Nikto in
# one .txt: 5 of 11 findings, all of them Nmap's).
_TOOL_BANNERS = (
    ("nmap", r"^(?:Starting Nmap \d|# Nmap [\d.]+ scan initiated)"),
    ("nikto", r"^- Nikto v\d"),
    ("sqlmap", r"\{[\d.]+#(?:stable|dev)\}|^sqlmap identified the following injection point"),
    ("gobuster", r"^Gobuster v\d"),
    ("dirb", r"^DIRB v\d"),
    ("ffuf", r"/'___\\"),
    ("feroxbuster", r"by Ben \"epi\" Risher"),
    ("hydra", r"^Hydra v\d.*\(c\)"),
    ("medusa", r"^Medusa v\d"),
    ("wpscan", r"WordPress Security Scanner by the WPScan Team"),
    # sslscan opens with its version and OpenSSL lines; "Connected to <ip>"
    # comes before "Testing SSL server" and holds the target's address.
    ("sslscan", r"^Version:\s+\S+\s*\n(?:OpenSSL|LibreSSL)"),
    ("sslscan", r"^Testing SSL server \S+ on port \d+"),
    ("testssl", r"^\s*testssl\.sh\s+(?:version\s+)?\d"),
    ("enum4linux", r"^Starting enum4linux"),
    ("masscan", r"^Starting masscan \d"),
    ("nuclei", r"projectdiscovery\.io"),
)


def _split_tool_segments(content: str) -> List[str]:
    """[content] unless it holds the output of two or more different tools; then
    one piece per tool run, each starting at the paragraph that holds its banner."""
    import re as _re
    if not isinstance(content, str) or PDF_TABLES_MARKER in content or content.lstrip()[:1] in "<{[":
        return [content]
    starts = []
    for tool, pat in _TOOL_BANNERS:
        for m in _re.finditer(pat, content, _re.MULTILINE):
            # Back to the start of the paragraph: sqlmap's, ffuf's and wpscan's
            # banners are ASCII art above the line that names them.
            para = content.rfind("\n\n", 0, m.start())
            starts.append((para + 2 if para >= 0 else 0, tool))
    starts = sorted(set(starts))
    runs = []
    for pos, tool in starts:
        if not runs or runs[-1][1] != tool:
            runs.append((pos, tool))
    if len({t for _p, t in runs}) < 2:
        return [content]
    cuts = [p for p, _t in runs]
    cuts[0] = 0                     # anything before the first banner stays with it
    return [content[a:b] for a, b in zip(cuts, cuts[1:] + [len(content)]) if content[a:b].strip()]


def parse_tool_file(filename: str, content: str, framework: str = "",
                    table_rows: Optional[Callable[[], List[str]]] = None) -> Tuple[List[Finding], Any]:
    """`table_rows`: a PDF's or Word document's table rows, given as a function
    and read only when they are needed. Only PentestReportParser reads them, and it comes after
    every scanner parser, so for a Burp, Nessus or other scanner PDF they were
    never used -- yet reading them parsed the PDF a second time and searched it
    for ruling lines: 30 s of a 50 s scan on PortSwigger's one-page Burp PDF.
    The result is the same as appending the rows under PDF_TABLES_MARKER."""
    # A byte-order mark in front of the JSON "{", the XML "<" or the CSV header
    # hid the format from every parser.
    if isinstance(content, str):
        content = content.lstrip("﻿")
    # A screenshot's OCR text ("ocr_<image>.txt"): repair what OCR breaks first
    # (ocr_text.py). A report file is parsed exactly as written.
    if isinstance(content, str) and str(filename or "").lower().startswith("ocr_"):
        from src.core.parsers.ocr_text import repair_ocr_text
        content = repair_ocr_text(content)
    segments = _split_tool_segments(content)
    if len(segments) > 1 and table_rows is not None:
        # A PDF with tables is never split by tool; whether it has any decides.
        rows = table_rows() or []
        table_rows = None
        if rows:
            content = content + PDF_TABLES_MARKER + "\n".join(rows)
            segments = [content]
    if len(segments) > 1:
        findings, extra = [], []
        for seg in segments:
            f_seg, e_seg = _parse_tool_file(filename, seg, framework)
            findings.extend(f_seg or [])
            if isinstance(e_seg, list):
                extra.extend(e_seg)
        _scrub(findings)
        _scrub(extra)
        return findings, extra
    findings, extra = _parse_tool_file(filename, content, framework, table_rows)
    _scrub(findings)
    _scrub(extra)
    return findings, extra


def _parse_tool_file(filename: str, content: str, framework: str = "",
                     table_rows: Optional[Callable[[], List[str]]] = None) -> Tuple[List[Finding], Any]:
    """
    Auto-detects file type and dispatches to the appropriate security tool parser.

    Parameters
    ----------
    filename : str
        Name / path of the file being parsed.
    content : str
        Extracted text content of the file.
    framework : str, optional
        The active audit framework (e.g. "vapt", "pqc", "iso").  When set to
        "vapt" the PQC binary fast-path is **skipped** so nmap screenshots,
        Nessus PDFs, and other VAPT evidence files are never misrouted through
        PQCParser.  Empty string / None falls back to the old behaviour (tries
        PQCParser for any binary extension) for callers that have not been
        updated yet.

    Detection strategy (in order):
    1. If framework == "vapt": skip the PQC binary fast-path entirely.
       Images / PDFs are returned as [] so bg_worker's OCR path handles them.
    2. PDF / DOCX / image files with binary extensions are tried through
       PQCParser FIRST when framework is PQC (or unspecified).  If PQCParser
       finds PQC findings, return them directly.  Otherwise fall through.
    3. Image files NOT claimed by PQCParser are returned early with [] -- they
       are visual PoC evidence screenshots with no XML/HTML scanner structure.
    4. All other files are tried against ALL_PARSERS using content-signature
       detection.
    5. If no parser claims the file, NessusParser handles it as a fallback.

    Returns (actionable_findings, extra_info/inventory).
    """
    _fw = str(framework or "").strip().lower()
    _is_vapt_framework = _fw == "vapt"

    # An XML scan arrives as a readable summary with the original document
    # appended under this marker (see doc_parsers' .xml branch). The summary is
    # for retrieval; the parsers recognise a scan by its SCHEMA, and they need
    # the document itself -- NessusParser looks for NessusClientData_v2, and its
    # XML reader cannot start on a page of prose. Splitting here keeps that one
    # concern in one place instead of teaching every parser to skip a preamble.
    _RAW_XML_MARKER = "\n[RAW XML]\n"
    if content and _RAW_XML_MARKER in content:
        content = content.split(_RAW_XML_MARKER, 1)[1]

    # A PDF's ruled tables, rebuilt from the page geometry by the VAPT worker
    # (doc_parsers.extract_pdf_table_rows) and appended under this marker. Only
    # the report-table parser reads them. The scanner parsers recognise their
    # own export by its structure and must never see these rows: appended to
    # the end of a Burp PDF they would be read as part of its last issue.
    _pdf_tables = ""
    if content and PDF_TABLES_MARKER in content:
        content, _pdf_tables = content.split(PDF_TABLES_MARKER, 1)

    # ── Stage 1: Binary document fast-path (PDF / DOCX / images) ─────────────
    # Route to PQCParser FIRST for PQC-relevant binary formats ONLY when the
    # active framework is PQC (or unknown).  When the caller is running a VAPT
    # scan, skip this entire block -- nmap screenshots / Nessus PDFs / Burp
    # reports must never be misclassified as PQC findings simply because they
    # mention "TLS 1.0" or "RSA" in their OCR text.
    ext_lower = __import__('os').path.splitext(filename.lower())[1]
    if ext_lower in _PQC_BINARY_EXTENSIONS and not _is_vapt_framework:
        # Looked up by type rather than by position. `ALL_PARSERS[-1]` relied on
        # PQCParser staying last in the list; appending any parser would have
        # silently handed this fast-path to the wrong one, with no error.
        pqc_p = next((p for p in ALL_PARSERS if isinstance(p, PQCParser)), None)
        if pqc_p is not None and pqc_p.can_parse(filename, content):
            res = pqc_p.parse(filename, content)
            findings, extra = res if isinstance(res, tuple) else (res, None)
            if findings:
                map_pqc_findings_list(findings)
                return findings, extra
        # PQCParser got nothing from this binary -- if it's an image, the
        # VAPT path handles it (OCR in bg_worker). If PDF/DOCX with no PQC
        # content, fall through to VAPT parsers below.
        if is_image_file(filename):
            # Images with no PQC content: route to caller for VAPT OCR.
            return [], None

    # ── Stage 2: Image fast-path for VAPT (non-PQC images) ───────────────────
    # Images with no binary-extension claim above are visual PoC screenshots.
    if is_image_file(filename):
        return [], None

    # ── Stage 3: Content-signature parser dispatch (text-based files) ────────
    #
    # The VAPT guard has to hold here too, not only on the binary fast-path above.
    # That earlier guard only covers _PQC_BINARY_EXTENSIONS, so a plain-text
    # scanner export skipped it entirely and fell into this loop, where PQCParser
    # sits last and claims anything mentioning cryptography. Confirmed on a real
    # file: VAPT/nessus_vulnerability_report.txt, which literally opens with
    # "Tenable Nessus Scan Report", was rejected by NessusParser.can_parse() and
    # claimed by PQCParser -- its HSTS and TLS vulnerabilities were replaced by
    # three duplicate "CBC-mode weak algorithm" PQC findings, and the Stage 3
    # NessusParser fallback below was never reached because the file had already
    # been claimed.
    #
    # Dropping PQCParser from the candidate list under the VAPT framework lets an
    # unclaimed scanner export reach that fallback, which is what it is for.
    _parsers = [
        p for p in ALL_PARSERS
        if not (_is_vapt_framework and p.__class__.__name__ == "PQCParser")
    ]
    for p in _parsers:
        _content = content
        if table_rows is not None and isinstance(p, PentestReportParser):
            _rows = table_rows() or []
            table_rows = None
            if _rows:
                _pdf_tables = "\n".join(_rows)
        if _pdf_tables and isinstance(p, PentestReportParser):
            _content = content + PDF_TABLES_MARKER + _pdf_tables
        if p.can_parse(filename, _content):
            res = p.parse(filename, _content)
            findings, extra = res if isinstance(res, tuple) else (res, None)
            # A parser that returned ONLY informational findings has still read
            # the file, and bg_worker uses both lists (`actionable + info`).
            # Judging the claim on `findings` alone discarded that work and fell
            # through to the fallback below: a compliance re-test report, whose
            # findings are all recorded as remediated, had its six real rows
            # thrown away and replaced by one finding titled "Executive" that
            # the Burp fallback scraped out of a heading.
            _informational = extra if isinstance(extra, list) else []
            if not findings and not _informational:
                print(
                    f"[VAPT PARSER WARNING] '{p.__class__.__name__}' recognized '{filename}' "
                    f"but extracted 0 findings. If this file genuinely contains vulnerabilities, "
                    f"the parser may not support this export's exact format/columns and needs review.",
                    flush=True
                )
            if findings or _informational:
                # PQCParser findings use the PQC-specific mapper (CIA, risk score,
                # per-algorithm remediation, OEM readiness, business priority).
                # All other parsers (Nessus, Burp, Nmap, Qualys, Trivy) use the
                # VAPT mapper. This is the gate that keeps the two pipelines separate.
                if p.__class__.__name__ == "PQCParser":
                    map_pqc_findings_list(findings)
                else:
                    map_findings_list(findings)
                    if _informational:
                        map_findings_list(_informational)
                return findings, extra

    # ── Stage 3: Fallback (general HTML/XML/PDF via NessusParser & BurpParser) ──
    findings, extra = NessusParser().parse(filename, content)
    if not findings:
        res_burp = BurpParser().parse(filename, content)
        findings, extra = res_burp if isinstance(res_burp, tuple) else (res_burp, None)
    if findings:
        map_findings_list(findings)
    return findings, extra

__all__ = [
    "Finding", "BaseParser", "is_image_file", "map_finding_to_control", "map_findings_list",
    "NessusParser", "NmapParser", "BurpParser", "QualysParser", "TrivyParser", "KaliParser",
    "ZapParser", "OpenVasParser", "NucleiParser", "TlsScanParser", "CodeScanParser",
    "PentestReportParser", "PQCParser",
    "parse_tool_file", "pqc_extract_text",
]
