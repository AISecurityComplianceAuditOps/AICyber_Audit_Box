# -*- coding: utf-8 -*-
"""
Multi-Tool Vulnerability Ingestion Engine (Nessus, Nmap, BurpSuite, Qualys, Trivy, CSV, HTML)
"""
from typing import List, Tuple, Any
from .finding_schema import Finding
from .base_parser import BaseParser, is_image_file
from .control_mapper import map_finding_to_control, map_findings_list, map_pqc_findings_list
from .nessus_parser import NessusParser
from .nmap_parser import NmapParser
from .burp_parser import BurpParser
from .qualys_parser import QualysParser
from .trivy_parser import TrivyParser
from .pqc_parser import PQCParser

ALL_PARSERS = [
    NessusParser(),
    NmapParser(),
    BurpParser(),
    QualysParser(),
    TrivyParser(),
    # PQCParser goes LAST -- its can_parse() is a weak-signal (2+ keyword) check
    # like Nessus's own fallback path, so it must never steal a file that a more
    # specific structural-signature parser above would have claimed.
    PQCParser(),
]

def parse_tool_file(filename: str, content: str) -> Tuple[List[Finding], Any]:
    """
    Auto-detects file type and dispatches to the appropriate security tool parser.

    Detection strategy (in order):
    1. Image files (PNG, JPG, JPEG, WEBP, BMP, TIFF etc.) are routed directly to
       the caller for OCR processing via extract_text(). They are NEVER passed to
       XML/HTML parsers regardless of what keywords appear in their filename.
       This eliminates false VAPT PARSER WARNINGs for screenshots named after tools
       (e.g. 'shot_burp_sqli.png' would previously match BurpParser by filename).
    2. All other files are tried against ALL_PARSERS using content-signature detection
       (magic bytes + structural XML/text tags). No filename keyword matching.
    3. If no parser claims the file, NessusParser handles it as a fallback (general
       HTML/XML). This is safe because NessusParser is the most format-agnostic.

    Returns (actionable_findings, extra_info/inventory).
    """
    # ── Stage 1: Image fast-path ──────────────────────────────────────────────
    # Images are visual PoC evidence screenshots. They carry no XML/CSV scanner
    # structure so no parser should ever claim them. Route to caller for OCR.
    if is_image_file(filename):
        # Return empty findings — the caller (bg_worker / retrieval pipeline)
        # already handles image OCR via extract_text(). Returning [] here avoids
        # the false-positive "extracted 0 findings" warning log.
        return [], None

    # ── Stage 2: Content-signature parser dispatch ────────────────────────────
    for p in ALL_PARSERS:
        if p.can_parse(filename, content):
            res = p.parse(filename, content)
            findings, extra = res if isinstance(res, tuple) else (res, None)
            if not findings:
                print(
                    f"[VAPT PARSER WARNING] '{p.__class__.__name__}' recognized '{filename}' "
                    f"but extracted 0 findings. If this file genuinely contains vulnerabilities, "
                    f"the parser may not support this export's exact format/columns and needs review.",
                    flush=True
                )
            if findings:
                # PQCParser findings use the PQC-specific mapper (CIA, risk score,
                # per-algorithm remediation, OEM readiness, business priority).
                # All other parsers (Nessus, Burp, Nmap, Qualys, Trivy) use the
                # VAPT mapper. This is the gate that keeps the two pipelines separate.
                if p.__class__.__name__ == "PQCParser":
                    map_pqc_findings_list(findings)
                else:
                    map_findings_list(findings)
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
    "NessusParser", "NmapParser", "BurpParser", "QualysParser", "TrivyParser", "PQCParser",
    "parse_tool_file"
]
