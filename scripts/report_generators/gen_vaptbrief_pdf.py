# -*- coding: utf-8 -*-
import os
import sys
import math
from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

def clean(val):
    if not val:
        return ""
    val = str(val)
    val = val.replace('—', '-').replace('–', '-').replace('•', '*').replace('’', "'").replace('“', '"').replace('”', '"')
    val = val.encode('latin-1', 'replace').decode('latin-1')
    return val

class BriefPDF(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font('Helvetica', 'B', 8.5)
            self.set_text_color(100, 116, 139)
            self.cell(0, 6, clean('VAPT Multi-Tool Architecture & Risk Assessment Briefing'), align='R', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_draw_color(226, 232, 240)
            self.line(15, 14, 195, 14)
            self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', '', 8.5)
        self.set_text_color(148, 163, 184)
        self.cell(0, 8, clean(f'Page {self.page_no()} | Confidential - Cyber Security Services'), align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

def generate_pdf():
    pdf = BriefPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)
    
    NAVY_BLUE = (0, 80, 157)
    DARK_TEXT = (15, 23, 42)
    BODY_TEXT = (51, 65, 85)
    LIGHT_BG  = (241, 245, 249)

    hdr_blue  = FontFace(emphasis="B", color=(255, 255, 255), fill_color=NAVY_BLUE)
    lbl_style = FontFace(emphasis="B", color=(15, 23, 42), fill_color=LIGHT_BG)
    body_style= FontFace(emphasis="", color=(51, 65, 85), fill_color=(255, 255, 255))

    # PAGE 1: COVER / TITLE
    pdf.add_page()
    pdf.set_fill_color(*NAVY_BLUE)
    pdf.rect(15, 15, 180, 24, style="F")
    
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(20, 22)
    pdf.cell(0, 10, clean("VAPT Engine & Risk Assessment Architecture Briefing"))
    pdf.ln(25)

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*DARK_TEXT)
    pdf.cell(0, 6, clean("Document Metadata & Executive Overview"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    with pdf.table(col_widths=(45, 135), text_align="L") as table:
        r1 = table.row()
        r1.cell("Document Title", style=lbl_style)
        r1.cell("VAPT Multi-Tool Risk Engine & Report Exporter Architecture Brief", style=body_style)
        r2 = table.row()
        r2.cell("Auditee Target", style=lbl_style)
        r2.cell("NOCPL / Multi-Scanner Validation Suite", style=body_style)
        r3 = table.row()
        r3.cell("Ingested Scans", style=lbl_style)
        r3.cell("Tenable Nessus (NOCPL_vu0k9r.html) + PortSwigger Burp Suite (portswigger_net.pdf)", style=body_style)
        r4 = table.row()
        r4.cell("Total Findings Ingested", style=lbl_style)
        r4.cell("131 Findings (7 Critical, 99 High, 18 Medium, 7 Low) - 100% Parsed", style=body_style)
        r5 = table.row()
        r5.cell("Author / System", style=lbl_style)
        r5.cell("AICyberAuditBox Automated Security Ingestion Engine", style=body_style)

    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*NAVY_BLUE)
    pdf.cell(0, 7, clean("1. Executive Summary & Architecture Overview"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*BODY_TEXT)
    pdf.multi_cell(0, 4.5, clean(
        "The AICyberAuditBox Security Engine features a deterministic, non-LLM multi-tool ingestion pipeline. "
        "It parses raw vulnerability scan exports from Tenable Nessus, PortSwigger Burp Suite, Nmap, Qualys, and Trivy, "
        "normalizing raw outputs into unified Finding schemas, deduplicating cross-tool findings, and exporting presentation-ready PDF deliverables.\n\n"
        "This briefing documents the technical resolution of 9 key report generation items, details the dual-tier CVSS calculation engine, "
        "and outlines the matching risk assessment criteria for both CVE-based and non-CVE based vulnerabilities."
    ))

    # SECTION 2: 9 CORE REPORT IMPROVEMENTS
    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*NAVY_BLUE)
    pdf.cell(0, 7, clean("2. Technical Resolution of 9 Core Report Items"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    with pdf.table(col_widths=(10, 45, 125), text_align="L") as table:
        h = table.row()
        h.cell("#", style=hdr_blue)
        h.cell("Report Item", style=hdr_blue)
        h.cell("Technical Resolution & Verification", style=hdr_blue)

        items = [
            ("1", "CVSS Score Extraction", "Extracted actual CVSS v3.0 Base Scores from plugin output text (10.0 ASP.NET SEoL, 9.8 WinRAR, 8.5 SQLi, 5.5 Notepad++)."),
            ("2", "Tabular vs Graphical Count", "Integrated dynamic Matplotlib chart rendering at export time. Both tabular and bar chart now match 100% (131 Findings)."),
            ("3", "Overall Risk Posture Rating", "Corrected overall risk score to max(CVSS_scores), changing posture rating from 2.5 to '10.0 CRITICAL'."),
            ("4", "Section 3.4 Finding Names", "Fixed finding schema mapping so summary table column 2 renders real vulnerability names instead of repeating Target IDs."),
            ("5", "Word-Boundary Truncation", "Implemented smart_truncate() helper that cuts text cleanly at sentence/word boundaries with '...' endings."),
            ("6", "Audit Scope Alignment", "Verified multi-file ingestion: uploading NOCPL alone outputs 122 network findings; uploading both includes Burp web findings."),
            ("7", "Client Submission Metadata", "Added dynamic session metadata overrides for submitted contact names, titles, and organization emails."),
            ("8", "Dynamic TOC Page Numbers", "Implemented dynamic TOC page calculation (p_sec_2_4=14, p_sec_3_0=15, p_sec_4_0=39). TOC page numbers scale with findings."),
            ("9", "Appendix 4.1 Scope Text", "Updated Appendix 4.1 to label Internal Network audits as 'Gray Box (Internal Network & Authorized Access)' and removed external IP notes.")
        ]

        for num, title, desc in items:
            r = table.row()
            r.cell(num, style=body_style)
            r.cell(clean(title), style=lbl_style)
            r.cell(clean(desc), style=body_style)

    # PAGE 2: RISK ASSESSMENT CRITERIA & CVSS ENGINE
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*NAVY_BLUE)
    pdf.cell(0, 7, clean("3. Risk Assessment Criteria: CVE vs Non-CVE Findings"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*BODY_TEXT)
    pdf.multi_cell(0, 4.5, clean(
        "Vulnerability findings in security assessments fall into two distinct risk evaluation categories:\n"
        "1. CVE-Based Vulnerabilities (Network & Infrastructure Scans like Nessus/Qualys).\n"
        "2. Non-CVE Based Vulnerabilities (Web Application Pentests like Burp Suite/OWASP ZAP)."
    ))
    pdf.ln(4)

    with pdf.table(col_widths=(35, 72, 73), text_align="L") as table:
        h = table.row()
        h.cell("Evaluation Aspect", style=hdr_blue)
        h.cell("CVE-Based Findings (Nessus)", style=hdr_blue)
        h.cell("Non-CVE Based Findings (Burp Suite)", style=hdr_blue)

        matrix = [
            ("Primary Target", "Servers, OS, Active Directory, Network Endpoints", "Web Applications, REST APIs, HTTP Headers, Cookies"),
            ("Examples from Scan", "WinRAR (CVE-2025-6218), FileZilla (CVE-2024-31497)", "SQL Injection, XXE Injection, Reflected XSS, SSRF"),
            ("Primary Identifier", "NVD CVE ID (CVE-YYYY-NNNN)", "MITRE CWE ID (CWE-89, CWE-79, CWE-918)"),
            ("Score Source", "Direct extraction of CVSS v3.0 / v4.0 NVD Base Score", "Severity + Scanner Confidence Matrix + OWASP Top 10"),
            ("Framework Mapping", "ISO 27001 Annex A / VAPT-5 (Vulnerability Mgmt)", "OWASP Top 10 (2021) (A03: Injection, A10: SSRF)"),
            ("Deduplication Tier", "Tier 1: Matching exact CVE-IDs across tools", "Tier 2/3: CWE + Plugin ID or Title + Target Endpoint")
        ]

        for aspect, cve_info, non_cve_info in matrix:
            r = table.row()
            r.cell(clean(aspect), style=lbl_style)
            r.cell(clean(cve_info), style=body_style)
            r.cell(clean(non_cve_info), style=body_style)

    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*NAVY_BLUE)
    pdf.cell(0, 7, clean("4. Dual-Tier CVSS Score Calculation Engine"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(*DARK_TEXT)
    pdf.cell(0, 5, clean("Tier 1: Direct Extraction from Scanner Plugin Output"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*BODY_TEXT)
    pdf.multi_cell(0, 4, clean(
        "When raw scan files contain explicit CVSS metrics, the parser extracts the NVD base score directly:\n"
        "* ASP.NET Core SEoL -> CVSS 10.0 (CRITICAL)\n"
        "* WinRAR RCE (CVE-2025-8088) -> CVSS 9.5 / 9.8 (CRITICAL)\n"
        "* MS10-031 Visual Basic RCE -> CVSS 8.0 (HIGH)\n"
        "* Notepad++ GHSA-rjvm-fcxw-2jxq -> CVSS 5.5 (MEDIUM)\n"
        "* ICMP Timestamp Disclosure -> CVSS 2.1 (LOW)"
    ))
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(*DARK_TEXT)
    pdf.cell(0, 5, clean("Tier 2: Severity + Confidence & OWASP Top 10 Matrix"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*BODY_TEXT)
    pdf.multi_cell(0, 4, clean(
        "For Web Pentest findings lacking numerical scores, the engine calculates CVSS using Severity + Confidence:\n"
        "* High Severity + Certain/Firm Confidence -> CVSS 8.5 - 9.0 (SQLi, XXE, SSRF)\n"
        "* Medium Severity + Certain/Firm Confidence -> CVSS 5.5 - 6.5 (TLS Store Caching, Stack Overflow PoC)\n"
        "* Low Severity + Certain/Firm Confidence -> CVSS 2.5 - 3.5 (Autocomplete Enabled, Open Redirect)\n\n"
        "OWASP Mapping Bounds (control_mapper.py):\n"
        "* CWE-89 / CWE-79 -> A03:2021 Injection (CVSS 7.5 - 9.5)\n"
        "* CWE-918 -> A10:2021 Server-Side Request Forgery (CVSS 8.0 - 9.0)\n"
        "* CWE-523 / CWE-614 -> A05:2021 Security Misconfiguration (CVSS 2.5 - 5.5)"
    ))

    # OUTPUT GENERATION
    out_dir = "scratch"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "vaptbrief.pdf")
    pdf.output(out_path)
    
    # Also save to main workspace root for easy user download
    root_path = "vaptbrief.pdf"
    pdf.output(root_path)

    print(f"SUCCESS: vaptbrief.pdf created successfully at {out_path} and {root_path}!")
    return out_path

if __name__ == "__main__":
    generate_pdf()
