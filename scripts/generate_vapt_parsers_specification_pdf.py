# -*- coding: utf-8 -*-
"""
Generate Master Specification PDF:
VAPT Parsers, Supported Tools, File Formats & Ingestion Pipeline
"""
import os
import sys
from fpdf import FPDF
from fpdf.enums import XPos, YPos

class VAPTSpecificationPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(71, 85, 105)  # Slate 600
        self.cell(0, 5, "AICyberAuditBox - VAPT Parsers, Supported Security Tools & File Ingestion Architecture", border=0, new_x=XPos.LMARGIN, new_y=YPos.TOP)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 5, "Technical Specification & Codebase Reference", border=0, align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        self.set_draw_color(203, 213, 225)  # Slate 300
        self.set_line_width(0.4)
        self.line(10, 14, 200, 14)
        self.ln(3)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)  # Slate 400
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

def sanitize(txt: str) -> str:
    return (
        str(txt)
        .replace("→", "->")
        .replace("←", "<-")
        .replace("“", '"')
        .replace("”", '"')
        .replace("‘", "'")
        .replace("’", "'")
        .replace("—", "-")
        .replace("–", "-")
        .replace("•", "-")
        .replace("✓", "[OK]")
        .replace("✔", "[OK]")
        .replace("❌", "[X]")
        .replace("⚡", "[FAST]")
        .replace("🔍", "[SCAN]")
        .replace("🚀", "[RUN]")
        .replace("⚙", "[CONFIG]")
        .replace("🛡", "[SEC]")
        .replace("₹", "INR ")
        .replace("≥", ">=")
        .replace("≤", "<=")
        .replace("≈", "~=")
        .replace("…", "...")
    )

def draw_title_banner(pdf: FPDF):
    pdf.ln(2)
    pdf.set_fill_color(15, 23, 42)  # Slate 900
    pdf.rect(10, pdf.get_y(), 190, 22, style="F")
    
    pdf.set_xy(14, pdf.get_y() + 3)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 6, "VAPT Parsers & Supported File Types Specification", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.set_x(14)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(148, 163, 184)  # Slate 400
    pdf.cell(0, 5, "Comprehensive Codebase Audit of Ingestion Engines, Scanners, File Formats, and Control Mappings", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_y(pdf.get_y() + 8)

def draw_section_heading(pdf: FPDF, title: str):
    if pdf.get_y() > 255:
        pdf.add_page()
    pdf.ln(3)
    pdf.set_fill_color(241, 245, 249)  # Slate 100
    pdf.set_draw_color(203, 213, 225)
    pdf.set_line_width(0.3)
    pdf.rect(10, pdf.get_y(), 190, 6.5, style="FD")
    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(15, 23, 42)
    pdf.set_x(13)
    pdf.cell(0, 6.5, sanitize(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1.5)

def draw_sub_heading(pdf: FPDF, title: str):
    if pdf.get_y() > 260:
        pdf.add_page()
    pdf.ln(1)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 4.5, sanitize(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(0.8)

def draw_paragraph(pdf: FPDF, text: str):
    if pdf.get_y() > 265:
        pdf.add_page()
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(51, 65, 85)
    pdf.multi_cell(190, 3.8, sanitize(text))
    pdf.ln(1)

def draw_callout(pdf: FPDF, title: str, text: str, alert_type="info"):
    if alert_type == "warning":
        fill_col = (254, 243, 199)
        border_col = (245, 158, 11)
        title_col = (146, 64, 14)
    elif alert_type == "success":
        fill_col = (236, 253, 245)
        border_col = (16, 185, 129)
        title_col = (6, 95, 70)
    else:
        fill_col = (240, 249, 255)
        border_col = (2, 132, 199)
        title_col = (7, 89, 133)

    lines = len(text) // 95 + 2
    height = max(12, lines * 3.6 + 5)
    
    if pdf.get_y() + height > 270:
        pdf.add_page()
        
    start_y = pdf.get_y()
    pdf.set_fill_color(*fill_col)
    pdf.set_draw_color(*border_col)
    pdf.set_line_width(0.4)
    pdf.rect(10, start_y, 190, height, style="FD")
    
    pdf.set_xy(13, start_y + 1.5)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*title_col)
    pdf.cell(0, 3.8, sanitize(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.set_xy(13, start_y + 5.5)
    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_text_color(51, 65, 85)
    pdf.multi_cell(184, 3.4, sanitize(text))
    pdf.set_y(start_y + height + 1.5)

def draw_table(pdf: FPDF, headers, rows, col_widths, align_list=None):
    if align_list is None:
        align_list = ["L"] * len(headers)
    
    pdf.ln(0.5)
    
    def print_header():
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_fill_color(30, 41, 59)
        pdf.set_text_color(255, 255, 255)
        pdf.set_draw_color(203, 213, 225)
        pdf.set_line_width(0.2)
        for i, h in enumerate(headers):
            pdf.cell(col_widths[i], 5, sanitize(h), border=1, fill=True, align="C")
        pdf.ln(5)

    print_header()
    
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(30, 41, 59)
    
    for r_idx, row in enumerate(rows):
        # Calculate max row height needed for multiline cells
        cell_height = 4.5
        if pdf.get_y() + cell_height > 270:
            pdf.add_page()
            print_header()
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(30, 41, 59)

        if r_idx % 2 == 1:
            pdf.set_fill_color(248, 250, 252)
        else:
            pdf.set_fill_color(255, 255, 255)
            
        for i, val in enumerate(row):
            pdf.cell(col_widths[i], cell_height, sanitize(val), border=1, fill=True, align=align_list[i])
        pdf.ln(cell_height)
    pdf.ln(1.5)

def build_pdf(output_path: str):
    pdf = VAPTSpecificationPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # ── BANNER ──
    draw_title_banner(pdf)
    
    # ── SECTION 1: EXECUTIVE SUMMARY & ARCHITECTURE ──
    draw_section_heading(pdf, "1. VAPT Parsing Architecture Overview")
    draw_paragraph(
        pdf,
        "The AICyberAuditBox platform provides a multi-layered security ingestion architecture specifically engineered "
        "for Vulnerability Assessment and Penetration Testing (VAPT) workflows. Security tools produce distinct output "
        "formats ranging from native XML/JSON structured trees to stylized HTML dashboards, console plaintext logs, "
        "and executive PDF/DOCX reports. The ingestion subsystem dispatches files dynamically using auto-detection "
        "and standardizes all findings into a unified data structure mapped deterministically to ISO 27001 & VAPT controls."
    )
    
    draw_callout(
        pdf,
        "Parser Orchestration Engine (src/core/parsers/__init__.py)",
        "The entry function parse_tool_file(filename, content) iteratively checks each registered parser via can_parse(). "
        "If a tool is recognized, it extracts actionable and informational findings, maps them to VAPT controls (VAPT-1..VAPT-15), "
        "and computes CVSS 3.1 base vectors. If no tool-specific parser matches, it falls back to NessusParser (which handles general HTML/XML) "
        "or doc_parsers.py text extraction.",
        alert_type="info"
    )

    # ── SECTION 2: DEDICATED TOOL PARSERS MATRIX ──
    draw_section_heading(pdf, "2. Dedicated Security Tool Parsers & Supported Extensions")
    draw_paragraph(
        pdf,
        "The codebase includes 5 dedicated parser modules in src/core/parsers/ inheriting from BaseParser. "
        "Each parser supports multiple export schemas, raw formats, and fallback modes:"
    )

    tool_headers = ["Parser Class", "Source Tool", "Supported Extensions", "Primary Export Formats Handled"]
    tool_col_widths = [32, 34, 38, 86]
    tool_rows = [
        [
            "NessusParser",
            "Tenable Nessus",
            ".nessus, .xml, .html, .htm, .txt",
            "1. Native XML (NessusClientData_v2 / ReportItem)\n2. HTML (div.section-wrapper)\n3. Plaintext heading regex fallback"
        ],
        [
            "BurpParser",
            "PortSwigger Burp Suite / ZAP",
            ".xml, .html, .htm, .txt",
            "1. Burp XML (<issues><issue>)\n2. HTML (<span class='BODH0'>)\n3. Plaintext hierarchy & HTTP request/response"
        ],
        [
            "NmapParser",
            "Nmap Network Scanner",
            ".nmap, .gnmap, .xml, .txt, .log",
            "1. XML (-oX, <nmaprun>)\n2. Grepable (-oG, Host: ... Ports: ...)\n3. Normal console (-oN, NSE vuln scripts & ports)"
        ],
        [
            "QualysParser",
            "Qualys VMDR / OpenVAS",
            ".csv, .xml, .txt",
            "1. Qualys CSV (dynamic column aliasing)\n2. Qualys Host List Detection XML\n3. OpenVAS GMP XML (<results><result>)"
        ],
        [
            "TrivyParser",
            "Aqua Trivy / Dep-Check",
            ".json",
            "1. Trivy JSON Schema v2 (Vulnerabilities[] & Misconfigurations[])\n2. OWASP Dependency-Check JSON"
        ]
    ]
    draw_table(pdf, tool_headers, tool_rows, tool_col_widths, align_list=["L", "L", "L", "L"])

    # ── SECTION 3: IN-DEPTH PARSER BREAKDOWNS ──
    draw_section_heading(pdf, "3. In-Depth Tool Parser Implementation & Field Extraction")
    
    # 3.1 Nessus
    draw_sub_heading(pdf, "3.1 Tenable Nessus Parser (src/core/parsers/nessus_parser.py)")
    draw_paragraph(
        pdf,
        "- Recognition: Triggered when filename ends with .nessus or content contains 'nessus', 'risk factor', or 'vulnerabilities by plugin'.\n"
        "- Native XML Mode: Parses <NessusClientData_v2> <ReportHost> and <ReportItem> elements. Extracts host-ip tags, pluginID, pluginName, "
        "severity (0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL), cvss3_base_score, cvss3_vector, cve tags, description, solution, and plugin_output.\n"
        "- HTML Export Mode: Searches for div.section-wrapper and extracts regex headers (e.g. '80336 (1) - PHP Multiple Vulnerabilities'), "
        "CVSS base scores, vectors, target host IPs and port/protocol tuples.\n"
        "- Plaintext Fallback: Splits PDF/DOCX-extracted Nessus report text using multiline regex headers."
    )

    # 3.2 Burp Suite
    draw_sub_heading(pdf, "3.2 Burp Suite & OWASP ZAP Parser (src/core/parsers/burp_parser.py)")
    draw_paragraph(
        pdf,
        "- Recognition: Triggered by filename containing 'burp', 'zap', 'portswigger' or content containing 'burp scanner', 'owasp zap', '<issues'.\n"
        "- XML Mode: Parses <issues><issue> nodes. Extracts name, host, path, severity, confidence, issueDetail, issueBackground, remediationDetail, "
        "and base64-decoded HTTP request/response evidence payloads.\n"
        "- HTML Mode: Traverses hierarchical class spans (.BODH0 category, .BODH1 instance, .TEXT descriptions, .rr_div HTTP traffic).\n"
        "- CVSS Scoring: Computes standards-compliant CVSS 3.1 base scores & vectors dynamically based on vulnerability type (e.g., SQLi=9.8, "
        "XXE=9.1, SSRF=8.6, Template Injection=8.5, XSS=7.2, Open Redirect=6.1)."
    )

    # 3.3 Nmap
    draw_sub_heading(pdf, "3.3 Nmap Network & Port Scanner Parser (src/core/parsers/nmap_parser.py)")
    draw_paragraph(
        pdf,
        "- Native XML Mode (-oX): Parses <nmaprun><host><ports><port> and <script id=... output=...> elements. Attributes NSE script findings "
        "directly to specific port/service combinations or host levels.\n"
        "- Grepable Mode (-oG): Parses tab-delimited 'Host: <ip>' and 'Ports: <id>/<state>/<proto>/<owner>/<service>/<version>/' strings to construct "
        "comprehensive Asset Inventories.\n"
        "- Normal Console Mode (-oN): Detects open ports and extracts NSE vulnerability script blocks (e.g. -vuln scripts, CVE matches). "
        "Applies deterministic keyword rules for unauthenticated services, weak TLS/SSL protocols, directory listings, and default credentials."
    )

    # 3.4 Qualys & OpenVAS
    draw_sub_heading(pdf, "3.4 Qualys VMDR & OpenVAS Parser (src/core/parsers/qualys_parser.py)")
    draw_paragraph(
        pdf,
        "- Qualys CSV Mode: Features dynamic column alias normalization matching 'qid', 'title', 'severity' (1..5 scale mapped to INFO..CRITICAL), "
        "'cve', 'threat', 'solution', 'ip', 'dns', 'port', and 'cvss'.\n"
        "- Qualys XML Mode: Supports Host List Detection XML (<HOST_LIST> with separate <GLOSSARY><QID_LIST> title lookup) and legacy <VULN> tags.\n"
        "- OpenVAS / Greenbone GMP Mode: Parses <report><results><result> XML nodes, mapping word-form threats and CVSS score bands."
    )

    # 3.5 Trivy
    draw_sub_heading(pdf, "3.5 Aqua Security Trivy Parser (src/core/parsers/trivy_parser.py)")
    draw_paragraph(
        pdf,
        "- Recognition: Triggered on .json files containing 'schemaversion' and 'vulnerabilities' or 'misconfigurations'.\n"
        "- Vulnerabilities (SCA): Extracts VulnerabilityID (CVE), PkgName, InstalledVersion, FixedVersion, CVSS v3/v2 scores, and automated remediation.\n"
        "- Misconfigurations (IaC): Parses Dockerfile, Terraform, and Kubernetes security policy violations with IDs, severities, and resolutions."
    )

    # ── SECTION 4: UNIVERSAL DOCUMENT INGESTION (DOC_PARSERS.PY) ──
    draw_section_heading(pdf, "4. Universal Document & Evidence Ingestion Engine (doc_parsers.py)")
    draw_paragraph(
        pdf,
        "In addition to standalone scanner files, the platform ingests VAPT audit evidence embedded in office documents, "
        "spreadsheets, slide decks, screenshots, and compressed archives:"
    )

    doc_headers = ["File Extension", "Engine / Library", "Extraction Logic & Capabilities"]
    doc_col_widths = [30, 42, 118]
    doc_rows = [
        [".pdf", "pdfplumber + doctr", "Native text extraction + Hybrid OCR on screenshots with OpenCV CLAHE contrast enhancement."],
        [".docx", "python-docx + doctr", "Document paragraphs, headings, data tables, and inline embedded screenshot OCR."],
        [".doc", "olefile (OLE binary)", "Legacy Word 97-2003 stream heuristic text and embedded JPEG/PNG extraction."],
        [".xlsx, .xls", "pandas + openpyxl", "Sheet row-range chunking, Col=Val format, ISO control ID tags, and pasted cell image OCR."],
        [".csv", "pandas / DictReader", "Header preservation, chunking, and raw CSV delimiter retention."],
        [".pptx", "python-pptx + doctr", "Slide titles, shape body text, speaker notes, tables, and slide diagram OCR."],
        [".ppt", "olefile (OLE binary)", "Legacy PowerPoint stream text and picture stream extraction."],
        [".html, .htm", "BeautifulSoup4 (lxml)", "Heading hierarchy, tables, <pre>/<code> blocks (banners/plugin output), base64 images."],
        [".xml", "ElementTree / BS4", "Smart pre-parsing for Burp, Nessus, Nmap, ZAP, Qualys, OpenVAS, or recursive key-value tree."],
        [".json", "json (Recursive)", "Smart flatteners for Trivy, ZAP, or generic nested dictionaries."],
        [".txt, .log", "UTF-8 Stream", "Direct fast-path UTF-8 text extraction and char-based chunking."],
        [".png, .jpg", "OpenCV + doctr", "Direct OCR with grayscale, CLAHE adaptive contrast, and denoising filter."],
        [".zip", "zipfile", "Auto-unpacking archive reader scanning all inner supported document types."]
    ]
    draw_table(pdf, doc_headers, doc_rows, doc_col_widths, align_list=["L", "L", "L"])

    # ── SECTION 5: CONTROL MAPPING & ENRICHMENTS ──
    draw_section_heading(pdf, "5. Unified Finding Schema & VAPT Control Mapping")
    draw_paragraph(
        pdf,
        "Every finding extracted from any VAPT tool or document is normalized into the Finding dataclass "
        "(src/core/parsers/finding_schema.py) and enriched via src/core/parsers/control_mapper.py:"
    )

    draw_paragraph(
        pdf,
        "• Finding Dataclass Fields: title, severity (CRITICAL, HIGH, MEDIUM, LOW, INFO), severity_score (CVSS float), cvss_vector, "
        "cve_list, target (IP/Port/URL), description, remediation, evidence (raw output), plugin_id, confidence, source_tool, "
        "category, cia_impact (e.g. C:HIGH | I:LOW | A:NONE), is_pii_exposed (boolean), remediation_actionable.\n"
        "• Deterministic VAPT Controls (VAPT-1 .. VAPT-15):"
    )

    vapt_ctrl_headers = ["Control ID", "Control Domain & Scope", "Trigger Vulnerability Keywords / Indicators"]
    vapt_ctrl_widths = [26, 54, 110]
    vapt_ctrl_rows = [
        ["VAPT-1", "External Perimeter & Attack Surface", "External IP discovery, exposed public interfaces, perimeter assets"],
        ["VAPT-2", "OSINT & DNS Reconnaissance", "Reconnaissance, OSINT, whois, DNS zone transfer, subdomains"],
        ["VAPT-3", "Network & Port Vulnerabilities", "Default fallback for network scanner port findings, host services"],
        ["VAPT-4", "Web Application & OWASP Top 10", "Web, http, https, xss, sqli, csrf, hsts, cookie, apache, nginx, iis, owasp"],
        ["VAPT-5", "Remote Code Execution & Traversal", "RCE, remote code execution, directory traversal, buffer overflow"],
        ["VAPT-6", "Authentication & Session Security", "Brute force, session fixation, JWT validation, credential stuffing"],
        ["VAPT-7", "Privilege Escalation & Access Control", "Privilege escalation, privesc, uac bypass, sudo misconfigurations"],
        ["VAPT-8", "Email Security & Social Engineering", "Phishing, SPF, DKIM, DMARC, email spoofing"],
        ["VAPT-9", "Wireless & Bluetooth Security", "Wireless, wifi, wpa, 802.11, rogue AP, bluetooth"],
        ["VAPT-10", "API & Microservice Security", "API, rest, graphql, jwt, swagger, openapi endpoint exposures"],
        ["VAPT-11", "Cloud & Container Security", "Docker, Kubernetes, AWS, S3 bucket misconfiguration, IAM roles"],
        ["VAPT-12", "Patch & Vulnerability Management", "Patch, outdated component, update required, EOL, fixed version"],
        ["VAPT-13", "Network Segmentation & Firewall", "Firewall, network segmentation, filtered port bypass"],
        ["VAPT-14", "Cryptography & Default Credentials", "Weak cipher, SSL/TLS v1.0, RC4, 3DES, plaintext, default password"],
        ["VAPT-15", "Logging, Monitoring & Incident Response", "Audit log failure, missing SIEM alerts, logging bypass"]
    ]
    draw_table(pdf, vapt_ctrl_headers, vapt_ctrl_rows, vapt_ctrl_widths, align_list=["C", "L", "L"])

    # ── SECTION 6: OWASP & DEDUPLICATION ──
    draw_section_heading(pdf, "6. OWASP Top 10 Mapping, CVSS Scoring & Deduplication")
    draw_paragraph(
        pdf,
        "1. OWASP Top 10 (2021) Mapping: The engine maintains an offline CWE-to-OWASP lookup table mapping CWE IDs "
        "(e.g., CWE-89 -> A03:2021 Injection, CWE-284 -> A01:2021 Broken Access Control, CWE-326 -> A02:2021 Cryptographic Failures, "
        "CWE-918 -> A10:2021 SSRF, CWE-937 -> A06:2021 Outdated Components).\n"
        "2. CVSS Vector Calculation: Uses the official offline cvss library for standards-based CVSS v2 and v3 calculation, "
        "with an integrated regex heuristic fallback to guarantee base scores are always populated.\n"
        "3. Cross-Run Deduplication: Finding.dedup_key() computes a SHA-256 fingerprint from (tool, plugin_id, CVE, normalized title, target). "
        "bg_worker.py pre-seeds existing database keys to prevent duplicate findings when re-scanning sessions."
    )

    draw_callout(
        pdf,
        "Codebase Compliance & Verification Notice",
        "All specifications in this document are derived directly from active source code in src/core/parsers/ and src/core/bg_worker.py. "
        "The system operates 100% offline with zero external API dependencies for parsing and control mapping.",
        alert_type="success"
    )

    # Save PDF
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)
    print(f"[+] Master VAPT Specification PDF generated at: {output_path}")

if __name__ == "__main__":
    out = os.path.join(os.getcwd(), "reports", "VAPT_Parsers_and_Supported_File_Types_Specification.pdf")
    build_pdf(out)
