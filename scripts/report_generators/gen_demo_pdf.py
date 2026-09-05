# -*- coding: utf-8 -*-
"""
Generator script for AICyberAuditBox_Demo_Full_Workflow_and_Architecture.pdf
Produces a comprehensive, presentation-ready PDF report for live demo presentations.
"""

import os
import sys
from fpdf import FPDF

class DemoArchitecturePDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 8.5)
        self.set_text_color(100, 110, 125)
        self.cell(0, 7, "AICyberAuditBox  |  Demo Presentation Architecture & Technical Workflow Report", border=False, align="L")
        self.set_draw_color(210, 215, 225)
        self.line(10, 15, 200, 15)
        self.ln(9)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 125, 135)
        self.cell(0, 8, f"Page {self.page_no()}  |  Confidential -- Enterprise Security & Live Demo Reference", align="C")

    def chapter_title(self, num, title):
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(14, 43, 92)  # Deep Navy Blue
        self.ln(4)
        self.cell(0, 8, f"{num}. {title}", border=False)
        self.ln(7)
        self.set_draw_color(14, 43, 92)
        self.set_line_width(0.6)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_line_width(0.2)
        self.ln(4)

    def section_title(self, title):
        self.set_font("Helvetica", "B", 10.5)
        self.set_text_color(30, 70, 135)
        self.ln(3)
        self.cell(0, 6, title, border=False)
        self.ln(6)

    def body_text(self, text):
        self.set_font("Helvetica", "", 9)
        self.set_text_color(45, 50, 60)
        self.multi_cell(0, 4.6, text)
        self.ln(2)

    def bullet_point(self, title, desc):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(20, 35, 60)
        self.cell(5, 4.6, "*", border=False)
        self.cell(48, 4.6, f"{title}:", border=False)
        self.set_font("Helvetica", "", 8.8)
        self.set_text_color(50, 55, 65)
        self.multi_cell(0, 4.6, desc)
        self.ln(1.5)

    def diagram_box(self, diagram_text):
        self.set_font("Courier", "", 7.0)
        self.set_fill_color(244, 247, 252)
        self.set_draw_color(210, 220, 235)
        self.set_text_color(25, 30, 40)
        
        lines = diagram_text.strip().split("\n")
        self.ln(1)
        for line in lines:
            if self.get_y() > 270:
                self.add_page()
            self.cell(0, 3.8, f"  {line}", border=False, fill=True)
            self.ln(3.8)
        self.ln(3)

    def callout_box(self, title, text, bg_rgb=(238, 244, 255), border_rgb=(100, 140, 210)):
        self.set_fill_color(*bg_rgb)
        self.set_draw_color(*border_rgb)
        self.set_font("Helvetica", "B", 9.5)
        self.set_text_color(14, 43, 92)
        
        self.ln(2)
        self.cell(0, 5, f"  {title}", border=False)
        self.ln(5)
        self.set_font("Helvetica", "", 8.8)
        self.set_text_color(40, 45, 55)
        self.multi_cell(0, 4.4, text)
        self.ln(2)

    def table_header(self, col_widths, headers):
        self.set_font("Helvetica", "B", 8.5)
        self.set_fill_color(14, 43, 92)
        self.set_text_color(255, 255, 255)
        for i, header in enumerate(headers):
            self.cell(col_widths[i], 7, header, border=1, align="C", fill=True)
        self.ln(7)

    def table_row(self, col_widths, data, is_even=False):
        self.set_font("Helvetica", "", 8)
        self.set_text_color(35, 40, 50)
        if is_even:
            self.set_fill_color(245, 248, 253)
        else:
            self.set_fill_color(255, 255, 255)
        
        for i, text in enumerate(data):
            self.cell(col_widths[i], 5.5, text, border=1, fill=True)
        self.ln(5.5)


def generate_demo_pdf():
    pdf = DemoArchitecturePDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Document Header Banner
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(14, 43, 92)
    pdf.cell(0, 10, "AICyberAuditBox", border=False, align="C")
    pdf.ln(8)
    
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(50, 70, 110)
    pdf.cell(0, 6, "Full System Working Workflow & Architecture (Live Demo Reference)", border=False, align="C")
    pdf.ln(6)
    
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, "Air-Gapped Offline AI Platform | ISO 27001 Agentic RAG | VAPT Scanner Engine", border=False, align="C")
    pdf.ln(8)

    # Executive Overview
    pdf.callout_box(
        "DEMO OVERVIEW & DESIGN PHILOSOPHY",
        "AICyberAuditBox is an enterprise-grade, offline-first security auditing platform. "
        "It provides dual auditing capabilities: (1) ISO 27001 Agentic RAG compliance auditing driven by LangGraph state machines "
        "and offline GGUF LLMs (Gemma-2 / Gemma-4) running on llama-server.exe; and (2) VAPT technical vulnerability report parsing "
        "using deterministic scanner engines mapped directly to OWASP Top 10 (2021) and CWE standards.\n"
        "100% of data processing, OCR, vector embedding, and LLM inference executes completely local and air-gapped without external network calls."
    )
    pdf.ln(3)

    # CHAPTER 1: COMPLETE WORKING WORKFLOW FROM SCRATCH
    pdf.chapter_title(1, "Complete End-to-End Working Workflow From Scratch")
    pdf.body_text(
        "The following 12-step sequence documents the complete technical workflow executed by AICyberAuditBox "
        "from the initial user HTTP request to final DB persistence and report compilation."
    )

    pdf.bullet_point("Step 1: Auth & Session", "User authenticates via ISO A.5.17 password policy, SHA-256 hashing, pyotp TOTP 2FA, receiving a signed PyJWT session token.")
    pdf.bullet_point("Step 2: Upload Guardrail", "src/core/input_guardrail.py validates file MIME types, file size boundaries, and screens for malicious prompt-injection payloads.")
    pdf.bullet_point("Step 3: Doc Extraction", "src/core/parsers/doc_parsers.py extracts text from PDF (pdfplumber/PyMuPDF), Word (.docx), Excel (.xlsx), PowerPoint (.pptx), CSV, & recursive ZIPs.")
    pdf.bullet_point("Step 4: Vision & OCR", "If pages are scanned images or dark terminal screenshots, DocTR / EasyOCR activates with OpenCV CLAHE contrast enhancement & denoising.")
    pdf.bullet_point("Step 5: PII Redaction", "src/core/pii_redactor.py automatically redacts credentials, secret keys, API tokens, IP addresses, and personal identifiable data before indexing.")
    pdf.bullet_point("Step 6: Embeddings", "Text is split into 200-500 token sliding windows. nomic-embed-text-v1.5.f16.gguf (llama-server port 11435) generates 768-dim dense vectors.")
    pdf.bullet_point("Step 7: Scoped RAG", "src/core/excel_scoping_parser.py parses uploaded audit checklists to restrict retrieval exclusively to designated locked filenames (Phase-1 Lock).")
    pdf.bullet_point("Step 8: LLM Pool", "llama-server.exe serves LLM completions on port 11434. LLMPortPoolManager handles multi-port lock leasing & adaptive timeouts based on concurrent sessions.")
    pdf.bullet_point("Step 9: LangGraph", "src/ai/audit_graph.py compiles a 4-node state graph (retrieve -> generate -> validate -> reflect) per control for structured evaluation.")
    pdf.bullet_point("Step 10: Grounding", "src/core/validator.py verifies evidence quotes are exact verbatim substrings in original docs, preventing LLM hallucination and prompt leakage.")
    pdf.bullet_point("Step 11: Knowledge Loop", "src/ai/knowledge_loop.py injects auditor feedback rules (AuditorLearningRule) into generator prompts to eliminate repeated false positives.")
    pdf.bullet_point("Step 12: Checkpoints", "Audit state is saved every 10 controls (AuditCheckpoint) to ShaktiDB PostgreSQL (with SQLite fallback) enabling seamless crash recovery.")

    # Flowchart Diagram Box
    pdf.ln(2)
    pdf.section_title("End-to-End System Architecture & Execution Pipeline Flow")
    
    flowchart_ascii = (
        "+---------------------------------------------------------------------------------------------------+\n"
        "|                              AICYBERAUDITBOX END-TO-END WORKFLOW                                  |\n"
        "|                                                                                                   |\n"
        "| [ USER DASHBOARD ] ---> [ FASTAPI ROUTER ] ---> [ INPUT GUARDRAIL SCANNER ]                        |\n"
        "|                                                       |                                           |\n"
        "|                                                       v                                           |\n"
        "|                                            [ DOCUMENT PARSER ENGINE ]                             |\n"
        "|                                        (PDF, Word, Excel, PPT, Zip, CSV)                          |\n"
        "|                                                       |                                           |\n"
        "|                                                       +---> [ DocTR / EasyOCR + OpenCV CLAHE ]    |\n"
        "|                                                       |                                           |\n"
        "|                                                       v                                           |\n"
        "|                                            [ PII REDACTION ENGINE ]                               |\n"
        "|                                                       |                                           |\n"
        "|                                                       v                                           |\n"
        "|                                            [ CHUNKER & VECTOR EMBEDDING ]                         |\n"
        "|                                           (nomic-embed-text @ Port 11435)                         |\n"
        "|                                                       |                                           |\n"
        "|                        +------------------------------+------------------------------+            |\n"
        "|                        |                                                             |            |\n"
        "|                        v                                                             v            |\n"
        "|            [ ISO 27001 AGENTIC RAG ]                                     [ VAPT PARSING PIPELINE ]|\n"
        "|      (LangGraph 4-Node State Machine)                                (Deterministic Parsers)      |\n"
        "|      * Retrieve (Scoped Excel Lock)                                  * Burp / Nessus / Nmap       |\n"
        "|      * Generate (Gemma @ Port 11434)                                 * Qualys / Trivy JSON        |\n"
        "|      * Validate (Verbatim Quote Match)                               * CWE -> OWASP Top 10 Map   |\n"
        "|      * Reflect  (Feedback Loop Retry)                                * CVSS Scoring & Dedup       |\n"
        "|                        |                                                             |            |\n"
        "|                        +------------------------------+------------------------------+            |\n"
        "|                                                       |                                           |\n"
        "|                                                       v                                           |\n"
        "|                                            [ DB REPLICATION & REPORT ]                            |\n"
        "|                                         ShaktiDB Postgres + SQLite Fallback                       |\n"
        "|                                         Executive PDF / Excel / JSON Export                       |\n"
        "+---------------------------------------------------------------------------------------------------+"
    )
    pdf.diagram_box(flowchart_ascii)

    # CHAPTER 2: ISO 27001 AUDIT MODULE
    pdf.add_page()
    pdf.chapter_title(2, "ISO 27001 Compliance Audit Module (Features & Working)")

    pdf.section_title("2.1 ISO 27001 Module Features & Capabilities")
    pdf.bullet_point("Agentic RAG Pipeline", "Powered by LangGraph state machine orchestrating 4 nodes (retrieve, generate, validate, reflect) per ISO control.")
    pdf.bullet_point("Intent-Based Evaluation", "Evaluates evidence against control intent and objectives (e.g. access control badge systems) rather than requiring rigid keywords.")
    pdf.bullet_point("Excel Two-Phase Scoping", "Locks control evaluation exclusively to user-designated evidence files specified in Excel checklists (Phase-1 restriction).")
    pdf.bullet_point("Strict Control Scope", "Enforces zero framework creep -- strictly isolates ISO 27001 requirements without hallucinating NIST, CIS, or SOC 2 rules.")
    pdf.bullet_point("Verbatim Quote Guardrail", "Requires cited evidence snippets to exist as verified exact substrings in raw source documents; triggers fast-path bypass when matched.")
    pdf.bullet_point("Knowledge Feedback Loop", "Injects past auditor corrections (AuditorLearningRule) into LLM generator context to continuously prevent repeated false positives.")
    pdf.bullet_point("Audit Checkpointing", "Saves execution state every 10 controls to ShaktiDB Postgres / SQLite, supporting instant audit resume after interruptions.")

    pdf.ln(2)
    pdf.section_title("2.2 ISO 27001 Module Technical Working Lifecycle")
    pdf.body_text(
        "1. Evidence Upload & Scoping: Auditor uploads evidence documents along with an ISO 27001 audit checklist (.xlsx).\n"
        "2. Excel Scoping Lock: src/core/excel_scoping_parser.py extracts target filenames and binds them to specific control IDs.\n"
        "3. Scoped Vector Retrieval: src/core/retrieval.py performs cosine similarity search using nomic-embed-text vectors filtered strictly by locked_filenames.\n"
        "4. Generator Node Execution: src/ai/audit_chains.py constructs prompt with ISO control objectives, retrieved context, and auditor learning rules, invoking Gemma-2 / Gemma-4 GGUF.\n"
        "5. Validation Node Processing: src/core/validator.py checks if the draft evidence quote matches verbatim in source text. If valid, passes directly; if invalid, triggers Reflection Node.\n"
        "6. Reflection Node Retry: The graph allows 1 reflection attempt to re-generate grounded reasoning. If still unverified, sets requires_human_review=True.\n"
        "7. Schema Normalization & Persistence: Results are written to the findings table with fields (status, severity_p1_p4, evidence_quote, confidence, hallucination_check)."
    )

    # CHAPTER 3: VAPT AUDIT MODULE
    pdf.ln(3)
    pdf.chapter_title(3, "VAPT Audit Module (Features & Working)")

    pdf.section_title("3.1 VAPT Module Features & Capabilities")
    pdf.bullet_point("Multi-Scanner Support", "Deterministic parsers for Burp Suite XML, Nessus XML/CSV, Nmap XML, Qualys XML/CSV, and Trivy container JSON scanner outputs.")
    pdf.bullet_point("Deterministic CWE-OWASP Map", "src/core/parsers/control_mapper.py maps CWE IDs directly to OWASP Top 10 (2021) categories using static lookup tables (0% hallucination risk).")
    pdf.bullet_point("CVSS Metric Engine", "Calculates standards-based CVSS v2, v3.1, and v4 base scores via cvss library with regex fallback for missing vector scores.")
    pdf.bullet_point("Multi-Tier Deduplication", "Deduplicates vulnerabilities across tools using CVE identifiers (primary), Tool+PluginID (secondary), or Tool+Normalized Title (tertiary).")
    pdf.bullet_point("Risk & CIA Enrichment", "Enriches findings with CIA Impact vector (Confidentiality, Integrity, Availability), PII Exposure flag, and developer-actionable remediation steps.")
    pdf.bullet_point("Unified Vulnerability Hub", "Aggregates multi-tool findings into a centralized, filterable security dashboard and unified executive vulnerability report.")

    pdf.ln(2)
    pdf.section_title("3.2 VAPT Module Technical Working Lifecycle")
    pdf.body_text(
        "1. Scanner File Upload: Auditor uploads raw scanner exports (e.g. Nessus .nessus XML, Burp .xml, Qualys .csv, Trivy .json).\n"
        "2. Security Inspection: src/core/input_guardrail.py screens file headers and structure for safety.\n"
        "3. Parser Dispatching: The system selects the corresponding parser (nessus_parser.py, burp_parser.py, qualys_parser.py, nmap_parser.py, trivy_parser.py).\n"
        "4. Schema Extraction: Scanner output is parsed into normalized Finding dataclass objects (title, severity, cvss_vector, cve_list, target, evidence, plugin_id).\n"
        "5. Control Mapping: ControlMapper translates CWE IDs to OWASP Top 10 categories (e.g. CWE-89 -> A03:2021-Injection).\n"
        "6. CVSS Calculation: Finding.__post_init__() executes _calculate_cvss_score() to resolve numeric severity scores (e.g. 9.8 Critical).\n"
        "7. Deduplication: Finding.dedup_key() generates unique fingerprint keys to merge duplicate findings from multiple scanner runs.\n"
        "8. Storage & Export: Findings are persisted to ShaktiDB Postgres / SQLite and exported to executive reports."
    )

    # CHAPTER 4: TECH STACK & LIBRARIES SPECIFICATION
    pdf.add_page()
    pdf.chapter_title(4, "Complete Technology Stack & Python Libraries Detail")

    pdf.body_text(
        "The table below details every architectural layer, framework, model, database, and Python library "
        "powering AICyberAuditBox."
    )

    col_w = [40, 50, 100]
    headers = ["Layer", "Technology / Library", "Role & Description in System"]
    
    tech_data = [
        ["API Framework", "FastAPI + Uvicorn", "Async RESTful backend engine with OpenAPI docs & CORS middleware"],
        ["LLM Server", "llama-server.exe (llama.cpp)", "Native C++ GGUF inference server hosting Gemma-2-2B & Gemma-4-E4B"],
        ["Embedding Server", "nomic-embed-text-v1.5", "Dense 768-dim vector embedding engine running on port 11435"],
        ["Agentic Engine", "LangGraph + LangChain", "State graph compiler orchestrating 4-node audit execution pipeline"],
        ["Vision & OCR", "DocTR / EasyOCR + OpenCV", "OCR page text extraction with CLAHE contrast & denoising pre-processing"],
        ["Master Database", "ShaktiDB (PostgreSQL)", "Master + 2-Slave replicated Docker container topology on port 15234"],
        ["Fallback Database", "SQLite (shakthidb_sqlite.db)", "Automatic fallback database when PostgreSQL is unreachable"],
        ["Cache & Metrics", "Redis", "Distributed session tracking, concurrency guardrails, & live audit metrics"],
        ["PDF Parser", "PyMuPDF (fitz) + pdfplumber", "High-performance PDF text, layout, and image region extraction"],
        ["Word Parser", "python-docx", "Structured text, table, and paragraph parsing from Microsoft Word docs"],
        ["Excel Parser", "openpyxl + pandas + xlrd", "Multi-sheet Excel parsing & scoping checklist filename extraction"],
        ["PPT Parser", "python-pptx", "Slide text & shape content extraction from PowerPoint presentations"],
        ["Security & Auth", "PyJWT + pyotp + passlib", "JWT session tokens, TOTP 2FA, SHA-256 password hashing"],
        ["CVSS Metrics", "cvss", "Standards-based CVSS v2, v3.1, v4 base score calculation"],
        ["XML Parsing", "lxml", "High-speed XML DOM parsing for Nessus, Burp, and Nmap scanner files"],
        ["PDF Generation", "fpdf2", "Programmatic PDF report compilation & styled layout generation"],
        ["Process Management", "LLMPortPoolManager", "Mutex lock leasing & round-robin multi-port LLM load balancing"],
        ["PII Redactor", "src/core/pii_redactor.py", "Automated regex & pattern-based PII/credential scrubbing engine"],
        ["Input Guardrail", "src/core/input_guardrail.py", "File validation, size limits, and malicious payload screening"],
        ["Packaging", "PyInstaller (spec file)", "Single-executable offline desktop application bundling"]
    ]

    pdf.table_header(col_w, headers)
    for idx, row in enumerate(tech_data):
        pdf.table_row(col_w, row, is_even=(idx % 2 == 0))

    pdf.ln(4)
    pdf.callout_box(
        "LIVE DEMO SUMMARY & VERIFICATION",
        "This PDF document summarizes the complete, production-ready backend workflow of AICyberAuditBox. "
        "All features detailed herein -- ISO 27001 Agentic RAG, VAPT Multi-Scanner Parsing, Scoped Retrieval, "
        "Grounding Validation, and Multi-Port llama.cpp Load Balancing -- are 100% functional, local, and air-gapped."
    )

    output_path = "AICyberAuditBox_Demo_Full_Workflow_and_Architecture.pdf"
    pdf.output(output_path)
    print(f"PDF successfully generated: {os.path.abspath(output_path)}")
    return output_path

if __name__ == "__main__":
    generate_demo_pdf()
