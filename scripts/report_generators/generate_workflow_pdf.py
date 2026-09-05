import os
import sys
from fpdf import FPDF

class AuditReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, "AICyberAuditBox -- Full Backend Architecture & Workflow Report", border=False, align="L")
        self.set_draw_color(200, 200, 200)
        self.line(10, 16, 200, 16)
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Page {self.page_no()} | Confidential -- Internal Architecture Documentation", align="C")

    def section_title(self, title):
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(20, 50, 110)
        self.ln(4)
        self.cell(0, 8, title, border=False)
        self.ln(8)
        self.set_draw_color(20, 50, 110)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def sub_section_title(self, title):
        self.set_font("Helvetica", "B", 10.5)
        self.set_text_color(40, 40, 40)
        self.ln(2)
        self.cell(0, 6, title, border=False)
        self.ln(6)

    def body_text(self, text):
        self.set_font("Helvetica", "", 9.5)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 5, text)
        self.ln(2)

    def code_box(self, code_text):
        self.set_font("Courier", "", 7.2)
        self.set_fill_color(245, 247, 250)
        self.set_draw_color(220, 225, 230)
        self.set_text_color(30, 30, 30)
        
        lines = code_text.strip().split("\n")
        self.ln(1)
        for line in lines:
            if self.get_y() > 270:
                self.add_page()
            self.cell(0, 4.0, f"  {line}", border=False, fill=True)
            self.ln(4.0)
        self.ln(3)

    def table_header(self, col_widths, headers):
        self.set_font("Helvetica", "B", 8.5)
        self.set_fill_color(20, 50, 110)
        self.set_text_color(255, 255, 255)
        for i, header in enumerate(headers):
            self.cell(col_widths[i], 7, header, border=1, align="C", fill=True)
        self.ln(7)

    def table_row(self, col_widths, data, is_even=False):
        self.set_font("Helvetica", "", 8)
        self.set_text_color(40, 40, 40)
        if is_even:
            self.set_fill_color(240, 244, 248)
        else:
            self.set_fill_color(255, 255, 255)
        
        for i, text in enumerate(data):
            self.cell(col_widths[i], 6, text, border=1, fill=True)
        self.ln(6)

def generate_pdf():
    pdf = AuditReportPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Document Header Title
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(20, 50, 110)
    pdf.cell(0, 10, "AICyberAuditBox -- Full Backend Architecture & Workflow", border=False, align="C")
    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 6, "PDF Flow, Embedding vs. LLM Roles, ISO Policy & VAPT Parsing Design", border=False, align="C")
    pdf.ln(8)

    # Section 1: Executive Overview
    pdf.section_title("1. Executive System Overview & Architecture")
    pdf.body_text(
        "The AICyberAuditBox is an enterprise-grade, offline AI-powered compliance auditing system designed for "
        "high-security corporate environments. It operates completely air-gapped on CPU-only hardware, evaluating complex corporate "
        "evidence documents against multi-framework compliance controls (ISO 27001, SOC 2, NIST SP 800-53, PCI-DSS)."
    )
    pdf.body_text(
        "The backend relies exclusively on a local llama-server.exe engine (hosting Gemma-4B GGUF on port 11434), "
        "a zero-token scoping engine, a hybrid vector/keyword retrieval engine, multi-tier database replication (ShakthiDB PostgreSQL "
        "with SQLite fallback), and a 4-Gate forensic validator."
    )

    # Section 2: PDF Upload to Audit Report Flowchart
    pdf.add_page()
    pdf.section_title("2. PDF Upload to Final Report: Step-by-Step Flowchart & Backend Pipeline")
    pdf.body_text(
        "This flowchart details the exact end-to-end backend sequence when an auditor uploads a PDF document into the system:"
    )

    upload_flowchart = (
        "+-----------------------------------------------------------------------------------+\n"
        "|               PDF UPLOAD TO FINAL COMPLIANCE REPORT: BACKEND WORKFLOW             |\n"
        "|                                                                                   |\n"
        "|  1. [ USER / CLIENT DASHBOARD ]                                                   |\n"
        "|        | (Uploads PDF file via HTTP POST /api/v1/audit/upload)                   |\n"
        "|        v                                                                          |\n"
        "|  2. [ FASTAPI ROUTER (src/api/endpoints/audit.py) ]                              |\n"
        "|        | (Validates file size, mime type, and generates async task ID)            |\n"
        "|        v                                                                          |\n"
        "|  3. [ DOCUMENT PARSER (src/core/parsers/doc_parsers.py) ]                         |\n"
        "|        | (Extracts text via pdfplumber / pypdf)                                   |\n"
        "|        |---> (If page is image/scanned PDF) -> [ EASYOCR ENGINE FALLBACK ]        |\n"
        "|        v                                                                          |\n"
        "|  4. [ SLIDING WINDOW CHUNKER (src/core/parsers/doc_parsers.py) ]                  |\n"
        "|        | (Splits text into 200-500 token chunks with 3-paragraph window)          |\n"
        "|        v                                                                          |\n"
        "|  5. [ EMBEDDING MODEL: nomic-embed-text via llama-server.exe /embedding ]         |\n"
        "|        | (Computes 768-dim dense vector embeddings per chunk)                     |\n"
        "|        v                                                                          |\n"
        "|  6. [ DATABASE STORAGE (ShakthiDB / sqlite-vec) ]                                 |\n"
        "|        | (Stores chunks, metadata, and sqlite-vec shadow index)                   |\n"
        "|        v                                                                          |\n"
        "|  7. [ ZERO-TOKEN SCOPING ENGINE (src/ai/scoping_engine.py) ]                      |\n"
        "|        | (Keyword matches document against controls; prunes 90% out-of-scope)     |\n"
        "|        v                                                                          |\n"
        "|  8. [ LANGGRAPH 4-AGENT PIPELINE (src/ai/audit_graph.py) ]                        |\n"
        "|        |                                                                          |\n"
        "|        +--> RETRIEVE NODE (Hybrid sqlite-vec 60% + BM25 40% search)               |\n"
        "|        |                                                                          |\n"
        "|        +--> GENERATIVE LLM: Gemma-4B via llama-server.exe /completion             |\n"
        "|        |    (Generates draft compliance findings, severity, and recommendations)  |\n"
        "|        |                                                                          |\n"
        "|        +--> VALIDATE NODE (4-Gate Forensic Validator: quotes & injection check)   |\n"
        "|        |                                                                          |\n"
        "|        +--> REFLECT NODE (If validation fails, LLM rewrites finding)             |\n"
        "|        v                                                                          |\n"
        "|  9. [ MASTER DB PERSISTENCE & ASYNC REPLICATION ]                                 |\n"
        "|        | (Writes verified audit findings; replicates Master -> Slaves)            |\n"
        "|        v                                                                          |\n"
        "| 10. [ REPORT EXPORTER (src/core/report_exporter.py) ]                             |\n"
        "|        | (Generates PDF / DOCX / Excel report matching client template)           |\n"
        "|        v                                                                          |\n"
        "|     [ DOWNLOADABLE COMPLIANCE AUDIT REPORT ]                                      |\n"
        "+-----------------------------------------------------------------------------------+"
    )
    pdf.code_box(upload_flowchart)

    # Section 3: Where Embedding Model vs LLM Comes Into Play
    pdf.add_page()
    pdf.section_title("3. Where Embedding Model vs. LLM Engine Comes into Play")
    pdf.body_text(
        "A critical architectural principle in AICyberAuditBox is the strict separation of responsibility between "
        "the Embedding Model (Nomic Embed Text) and the Generative Large Language Model (Gemma 4B):"
    )

    pdf.sub_section_title("A. Where the EMBEDDING MODEL comes into play:")
    embed_points = [
        ("1. Ingestion Vectorization (Document Ingestion Phase)", "When a PDF is uploaded and chunked, every text chunk is sent to llama-server.exe /embedding endpoint using nomic-embed-text-v1.5. It converts raw text into a 768-dimensional numerical vector representing its semantic meaning, stored in sqlite-vec."),
        ("2. Control Query Vectorization (Search Phase)", "When evaluating a specific compliance control (e.g. ISO 27001 Access Control), the control requirement query is converted into a 768-dim vector using the embedding model."),
        ("3. Hybrid Semantic Search (Retrieval Phase)", "In hybrid_search() (src/core/retrieval.py), cosine similarity is calculated between the control query vector and all stored document chunk vectors to retrieve the most relevant evidence (weighted at 60%).")
    ]
    for title, desc in embed_points:
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(20, 50, 110)
        pdf.cell(0, 4.2, f"  * {title}", border=False)
        pdf.ln(4.2)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 4.2, f"    {desc}")
        pdf.ln(1)

    pdf.sub_section_title("B. Where the GENERATIVE LLM comes into play:")
    llm_points = [
        ("1. Draft Finding Generation (LangGraph Generate Node)", "In generate_node() (src/ai/audit_graph.py), after evidence chunks are retrieved, the prompt + evidence + control requirement is sent to llama-server.exe /completion (hosting Gemma-4B GGUF). The LLM reasons over the evidence, determines compliance status, assigns severity, and drafts remediation text."),
        ("2. Self-Correction & Rewrite Loop (LangGraph Reflect Node)", "In reflect_node() (src/ai/audit_graph.py), if the 4-Gate Forensic Validator flags hallucination or verbatim quote mismatches, the LLM is called again with the error feedback to rewrite and correct the draft finding.")
    ]
    for title, desc in llm_points:
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(20, 50, 110)
        pdf.cell(0, 4.2, f"  * {title}", border=False)
        pdf.ln(4.2)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 4.2, f"    {desc}")
        pdf.ln(1)

    # Section 4: ISO 27001 vs VAPT Parsing Design
    pdf.add_page()
    pdf.section_title("4. ISO 27001 Policy vs. VAPT Scanner Parsing Design")
    pdf.body_text(
        "The system incorporates two distinct parsing architectures tailored specifically for governance policy documents vs. automated vulnerability scanners:"
    )

    pdf.sub_section_title("A. ISO 27001 Policy & Governance Parsing Design (doc_parsers.py):")
    iso_design = [
        ("1. Multi-Format Native Readers", "Uses pdfplumber/pypdf for PDF, python-docx for Word DOCX, and openpyxl/pandas for Excel audit matrices."),
        ("2. EasyOCR Visual Fallback", "For scanned or image-based PDFs, auto-triggers EasyOCR engine to convert image pixels into text."),
        ("3. Sliding-Window Paragraph Chunker", "Splits text into 200-500 token chunks using 3 consecutive paragraphs per window (stride 1 paragraph, hard cap 2,000 chars) to preserve complete policy context clauses."),
        ("4. Zero-Token Scope Pruning", "scoping_engine.py matches document text against ISO 27001 controls (A.5 to A.18), pruning 90% out-of-scope controls WITHOUT LLM tokens.")
    ]
    for title, desc in iso_design:
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(20, 50, 110)
        pdf.cell(0, 4.2, f"  * {title}", border=False)
        pdf.ln(4.2)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 4.2, f"    {desc}")
        pdf.ln(1)

    pdf.sub_section_title("B. VAPT Vulnerability Scanner Parsing Design (src/core/parsers/):")
    vapt_design = [
        ("1. Multi-Scanner XML/JSON Ingestion", "Dedicated parsers for Burp Suite (burp_parser.py), Nessus (nessus_parser.py), Nmap (nmap_parser.py), Qualys (qualys_parser.py), and Trivy (trivy_parser.py)."),
        ("2. Unified Finding Schema", "finding_schema.py standardizes all scanner findings into a single structure: title, severity, cve_list, cwe_id, description, recommendation, evidence, plugin_id, target."),
        ("3. Deterministic CVE-First Deduplication", "get_dedup_key() uses a CVE-First -> Plugin-ID -> Title-last strategy to prevent accidentally merging distinct vulnerabilities on the same target."),
        ("4. Published MITRE CWE -> OWASP Top 10 Mapping", "map_finding_to_owasp() uses an official published lookup table (e.g. CWE-89 -> A03:2021 Injection, CWE-22 -> A01:2021 Access Control). Zero LLM needed."),
        ("5. Deterministic VAPT Control Mapping", "map_finding_to_control() maps findings to standard VAPT categories (VAPT-1 to VAPT-15) based on vulnerability taxonomy (RCE -> VAPT-5, Weak SSL/TLS -> VAPT-14, Web -> VAPT-4, Outdated Patches -> VAPT-12) with 100% deterministic precision.")
    ]
    for title, desc in vapt_design:
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(20, 50, 110)
        pdf.cell(0, 4.2, f"  * {title}", border=False)
        pdf.ln(4.2)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 4.2, f"    {desc}")
        pdf.ln(1)

    # Section 5: Complete Function & Module Inventory
    pdf.add_page()
    pdf.section_title("5. Complete Module & Function Inventory (File-by-File)")

    modules = [
        {
            "file": "src/db/database.py",
            "desc": "Core Database Connection & Replication Layer",
            "funcs": [
                ("init_db()", "Initializes PostgreSQL Master ('eng_m') & Slaves ('eng_s1', 'eng_s2'). Auto-switches to SQLite if Postgres unreachable."),
                ("reconcile_schemas(engine)", "Inspects DB tables vs SQLAlchemy models, dropping and recreating mismatched tables safely."),
                ("replicate_changes()", "Triggers async background thread to replicate write ops from Master to Slave 1 & Slave 2."),
                ("_replication_worker_loop()", "Daemon worker processing queued replication jobs with debouncing to prevent thrashing."),
                ("RoutingSession.get_bind()", "Smart session router directing write ops to Master engine and read queries load-balanced to Slaves."),
                ("get_db()", "FastAPI dependency generator yielding database sessions with automatic cleanup.")
            ]
        },
        {
            "file": "src/api/main.py & src/api/endpoints/",
            "desc": "REST API Gateway & Route Controllers",
            "funcs": [
                ("main.app", "FastAPI app instance with CORS, security headers, rate limiters, and router mount points."),
                ("audit.start_audit_endpoint()", "Receives audit request, initializes background worker, returns async task ID."),
                ("audit.get_audit_status()", "Returns real-time progress, completed controls, current step, and finding summary."),
                ("audit.upload_audit_documents()", "Handles multi-file uploads (PDF, DOCX, XLSX, images), triggering ingestion parser."),
                ("audit.export_audit_report()", "Generates downloadable PDF/DOCX/Excel audit report matching client template."),
                ("auth.login_user() / verify_totp_2fa()", "Authenticates credentials, validates 6-digit TOTP code (pyotp), issues JWT tokens."),
                ("controls.get_controls_catalog()", "Returns active control framework standards (ISO 27001, SOC 2, NIST, PCI-DSS)."),
                ("license.verify_license_key()", "Validates client RSA digital license signature and wallet tokens.")
            ]
        },
        {
            "file": "src/ai/audit_graph.py & src/ai/scoping_engine.py",
            "desc": "LangGraph State Machine & Zero-Token Scoping Engine",
            "funcs": [
                ("prune_out_of_scope_controls()", "Zero-LLM keyword matcher that filters controls with no relevance, saving 90% execution time."),
                ("build_audit_graph()", "Compiles the 4-node LangGraph StateGraph (retrieve -> generate -> validate -> reflect)."),
                ("retrieve_node(state)", "Fetches relevant evidence chunks using hybrid search for the active control."),
                ("generate_node(state)", "Invokes local Gemma LLM via llm_client to construct compliance audit draft findings."),
                ("validate_node(state)", "Executes 4-Gate Forensic Validator on draft finding, checking hallucination & verbatim evidence."),
                ("reflect_node(state)", "Rewrites non-compliant draft findings using validator error state feedback."),
                ("should_continue(state)", "Conditional edge directing state to 'reflect' if validation fails (max 3 retries) or 'END' if passed.")
            ]
        },
        {
            "file": "src/core/retrieval.py & src/core/llm_client.py",
            "desc": "Hybrid Search Engine & Dedicated llama-server.exe Client",
            "funcs": [
                ("hybrid_search()", "Combines 60% vector similarity + 40% BM25 keyword search scores via Reciprocal Rank Fusion (RRF)."),
                ("_init_sqlite_vec()", "Loads C-extension sqlite-vec native vector engine for ultra-fast local embeddings search."),
                ("python_cosine_search()", "Vector search fallback using NumPy cosine similarity when C-extension is unavailable."),
                ("query_llm()", "Sends completion requests directly to llama-server.exe on port 11434."),
                ("query_llm_stream()", "Streams tokens directly from local llama-server.exe completion endpoint."),
                ("get_embedding()", "Fetches 768-dim text vectors directly from llama-server.exe /embedding endpoint.")
            ]
        },
        {
            "file": "src/core/validator.py & src/core/parsers/",
            "desc": "4-Gate Forensic Validator & Document Parsers",
            "funcs": [
                ("validate_finding()", "Main orchestrator running all 4 validation gates on drafted audit finding."),
                ("gate1_injection_check()", "Scans drafted finding for prompt injection leaks, system instruction echoes, or key bypasses."),
                ("gate2_verbatim_check()", "Verifies quoted evidence text directly exists within ingested document text."),
                ("gate3_similarity_check()", "Calculates semantic similarity between control requirement and draft finding recommendation."),
                ("gate4_schema_check()", "Validates json output schema, severity enum (Compliant, Non-Compliant, Observation), & control IDs."),
                ("doc_parsers.parse_document()", "Universal entry router selecting specific document parser based on file mime/extension."),
                ("easyocr_fallback_parse()", "OCR fallback engine extracting text from scanned PDF pages and images using EasyOCR."),
                ("control_mapper.map_finding_to_owasp()", "Deterministic OWASP Top 10 mapper using published MITRE CWE lookup table."),
                ("control_mapper.map_finding_to_control()", "Deterministic VAPT control mapper mapping findings to VAPT-1..VAPT-15.")
            ]
        }
    ]

    for mod in modules:
        pdf.sub_section_title(f"File: {mod['file']} ({mod['desc']})")
        for fn_name, fn_desc in mod["funcs"]:
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.set_text_color(20, 50, 110)
            pdf.cell(0, 4.5, f"  * {fn_name}", border=False)
            pdf.ln(4.5)
            pdf.set_font("Helvetica", "", 8.5)
            pdf.set_text_color(50, 50, 50)
            pdf.multi_cell(0, 4.5, f"    {fn_desc}")
            pdf.ln(1)
        pdf.ln(2)

    # Section 6: Comprehensive Fallback System Matrix
    pdf.add_page()
    pdf.section_title("6. Comprehensive System Fallback Matrix")
    pdf.body_text(
        "To ensure 100% operational uptime and zero audit failures under resource constraints or service crashes, "
        "the AICyberAuditBox incorporates multi-tier automated fallback systems:"
    )

    col_w = [25, 35, 35, 45, 50]
    headers = ["Component", "Primary Engine", "Fallback Engine", "Trigger Condition", "Behavior / Resolution"]
    pdf.table_header(col_w, headers)

    fallback_rows = [
        ("Database", "ShakthiDB (Postgres)", "SQLite File DB", "PostgreSQL offline / unreachable on 15234", "Switches seamlessly to ./data/sqlite/shakthidb_sqlite.db with WAL mode enabled."),
        ("LLM Engine", "llama-server.exe", "Dedicated Instance", "Port 11434 default endpoint", "Routes all completions directly to local llama-server.exe (Gemma-4B)."),
        ("Vector Search", "sqlite-vec (C-Ext)", "Python Cosine (NumPy)", "sqlite-vec load extension failure", "Executes exact Flat Cosine similarity in pure Python with 100% recall precision."),
        ("Doc Parsing", "Native PDF/DOCX Parser", "EasyOCR Engine", "Scanned PDF / image-only PDF page", "Automatically invokes EasyOCR engine to perform OCR text extraction."),
        ("RAG Ingestion", "Chunked Vector RAG", "Full Text RAG Bypass", "Uploaded document size < 35KB", "Bypasses vector chunking and feeds complete document text into LLM prompt for 100% context recall.")
    ]

    for idx, row in enumerate(fallback_rows):
        pdf.table_row(col_w, list(row), is_even=(idx % 2 == 1))

    pdf.ln(4)

    # Section 7: LangGraph Self-Correction & Validator Flow
    pdf.section_title("7. LangGraph 4-Agent Audit & Self-Correction Flowchart")
    pdf.body_text(
        "Every scoped compliance control is processed through the LangGraph State Machine. If the 4-Gate Forensic Validator "
        "detects hallucinations or verbatim check failures, the system routes the finding into a self-correction loop:"
    )

    agent_diag = (
        "               +------------------------------+\n"
        "               |      Start Control Audit     |\n"
        "               +------------------------------+\n"
        "                              |\n"
        "                              v\n"
        "              +--------------------------------+\n"
        "              |     1. RETRIEVE SUBAGENT       |\n"
        "              | (Hybrid Vector + BM25 Evidence)| \n"
        "              +--------------------------------+\n"
        "                              |\n"
        "                              v\n"
        "              +--------------------------------+\n"
        "              |     2. AUDITOR SUBAGENT        |\n"
        "              | (Draft Compliance Finding)     |\n"
        "              +--------------------------------+\n"
        "                              |\n"
        "                              v\n"
        "              +--------------------------------+\n"
        "              |     3. VALIDATOR SUBAGENT      |\n"
        "              | (4-Gate Verification Check)    |\n"
        "              +--------------------------------+\n"
        "                              |\n"
        "                 / \\                       / \\\n"
        "                /   \\                     /   \\\n"
        "       Passed? /     \\ Yes               /     \\ No (Max 3 retries)\n"
        "              <       > --------------> <       >\n"
        "               \\     /                   \\     /\n"
        "                \\   /                     \\   /\n"
        "                 \\ /                       \\ /\n"
        "                  |                         |\n"
        "                  v                         v\n"
        "+-----------------------------------+  +-----------------------------------+\n"
        "|        Save Finding to DB         |  |       4. REFLECT SUBAGENT         |\n"
        "|  (ShakthiDB / SQLite Persistence) |  |  (Rewrite Finding with Feedback)  |\n"
        "+-----------------------------------+  +-----------------------------------+\n"
        "                                                    |\n"
        "                                                    +---> (Loop back to Auditor)"
    )
    pdf.code_box(agent_diag)

    # Output file path
    output_pdf_path = os.path.join(os.getcwd(), "AICyberAuditBox_Full_Backend_Workflow_Report.pdf")
    pdf.output(output_pdf_path)
    print(f"Successfully generated PDF: {output_pdf_path}")
    return output_pdf_path

if __name__ == "__main__":
    generate_pdf()
