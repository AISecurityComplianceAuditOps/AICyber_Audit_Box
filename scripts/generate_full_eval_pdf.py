"""
generate_full_eval_pdf.py
Generates a professional white-template PDF version of the FULL_PROJECT_EVALUATION.md report.
Includes all flow and sequence diagrams.
Run: python scripts/generate_full_eval_pdf.py
"""

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace
import os, re


OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "FULL_PROJECT_EVALUATION.pdf")

# ── Colour Palette ──────────────────────────────────────────────────────────
DARK_BG      = (15,  23,  42)
ACCENT_BLUE  = (59, 130, 246)
LIGHT_GRAY   = (245, 247, 250)
DARK_TEXT    = (15,  23,  42)
BODY_TEXT    = (51,  65,  85)
WHITE        = (255, 255, 255)
MID_GRAY     = (180, 180, 180)

# ── ASCII Diagrams ──────────────────────────────────────────────────────────
ARCH_DIAGRAM = """
               +----------------------------+
               |   Streamlit UI Dashboard   |
               +----------------------------+
                             |
                             v
               +----------------------------+
               | LangGraph State Machine    |
               +----------------------------+
                 /           |            \\
                /            |             \\
               v             v              v
        +------------+ +------------+ +-------------+
        | RAG Engine | | Validator  | | llama.cpp   |
        +------------+ +------------+ | C++ Backend |
              \\              /        +-------------+
               \\            /
                v          v
        +----------------------------+
        | ShaktiDB PostgreSQL/SQLite |
        +----------------------------+
"""

SEQ_DIAGRAM = """
  +---------------+        +---------------------+        +----------------------+
  | LLM Generator |        | Grounding Validator |        | LangGraph Reflection |
  +---------------+        +---------------------+        +----------------------+
          |                           |                              |
          | --- Draft Report -------> |                              |
          |     (Status: NON_COMPLIANT|                              |
          |      Evidence: NOT_FOUND) |                              |
          |                           | -- Runs potential_           |
          |                           |    evidence_exists() scan -> |
          |                           |                              |
          |                           | <--- Keywords found -------- |
          |                           |      in DB chunks            |
          |                           |                              |
          |                           | === Validation REJECTED! === |
          |                           | --- Trigger Retry ---------> |
          |                           |     (Injected context chunk) |
          | <--- Re-evaluate Context -+                              |
          |     (Iteration 2)         |                              |
          v                           v                              v
"""

QUICK_DEEP_DIAGRAM = """
                      +-----------------------------+
                      |   Initialize Audit State    |
                      +-----------------------------+
                                     |
                                     v
                      +-----------------------------+
                      |      LLM Draft Report       |
                      |  (Compliance & Evidence)    |
                      +-----------------------------+
                                     |
                                     v
                      +-----------------------------+
                      |  Grounding Validation Gate  |
                      +-----------------------------+
                               /           \\
                 (Passed Gates)             (Failed Gates)
                     /                               \\
                    v                                 v
      +------------------------+             +------------------+
      |  Approve Draft Report  |             | Audit Mode Check |
      +------------------------+             +------------------+
                    |                           /            \\
                    |                 (Quick Mode)          (Deep Mode)
                    |                       /                  \\
                    |                      v                    v
                    |         +-------------------+    +--------------------+
                    |         | Accept Validator  |    | LangGraph Reflection|
                    |         | Status Override   |    | Injects missing DB |
                    |         | (PARTIAL / HUMAN) |    | chunks into context|
                    |         +-------------------+    +--------------------+
                    |                  |                         |
                    |                  |                  (Up to 2 Retries)
                    |                  |                         |
                    v                  v                         v
              +-----------------------------------------------------+
              |           Compile & Write Final PDF Report          |
              +-----------------------------------------------------+
"""

VAPT_DIAGRAM = """
      [ 1. Ingest Raw logs ] --------> [ 2. Parse scan files ]
      (Nmap, Nessus, Burp, docs)      (Extract ports/ciphers/vulns)
                                                    |
                                                    v
      [ 4. Hybrid RAG Retrieval ] <---- [ 3. Auditor Selects Framework ]
      (60% Vector + 40% Keyword)       (VAPT checklist VAPT-1 to 15)
                   |
                   v
      [ 5. Prompt injection ] --------> [ 6. LLM Evaluation ]
      (Auditor agent instructions)    (Gemma 4B / Qwen draft)
                                                    |
                                                    v
      [ 8. Reflection Node ] <-------- [ 7. 4-Gate Grounding Validator ]
      (LangGraph self-correction loop) (Check exact IP, port & version)
              |                                     | (Passed)
              v (Max 2 retries)                     v
      [ Retry LLM Draft ]             [ 9. Save to database & Export ]
                                      (Official TÜV SÜD PDF & DOCX)
"""

CUSTOM_CONTROL_DIAGRAM = """
      [ Auditor Input ] ---------------------> [ Excel Ingestion (XLSX) ]
      (UI Form: ID, Name, Desc, Evidence)      (3-Column Upload Ingestion)
                         \\                         /
                          v                       v
                    +------------------------------------+
                    | add_custom_control() DB Writer     |
                    +------------------------------------+
                                      |
                                      v
                    +------------------------------------+
                    | ShaktiDB Table: custom_controls    |
                    +------------------------------------+
                                      |
                                      v
                    +------------------------------------+
                    | _load_custom_use_cases() Loader    |
                    | (Combines defaults + custom active)|
                    +------------------------------------+
                                      |
                                      v
                    +------------------------------------+
                    | Dynamic Scoping & Keyword Matcher  |
                    | (Binds control to matching docs)   |
                    +------------------------------------+
                                      |
                                      v
                    +------------------------------------+
                    |      Offline Compliance Audit      |
                    |    (RAG -> Gemma -> Validator)     |
                    +------------------------------------+
"""

class FullEvalPDF(FPDF):
    def header(self):
        self.set_draw_color(*MID_GRAY)
        self.set_line_width(0.2)
        self.line(10, 8, 200, 8)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*MID_GRAY)
        self.set_xy(10, 3)
        self.cell(0, 5, "AICyberAuditBox  --  Full Project Evaluation (EVL) Report", align="L")
        self.set_xy(0, 3)
        self.cell(200, 5, f"Page {self.page_no()}", align="R")
        self.ln(10)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*MID_GRAY)
        self.cell(0, 6, "CONFIDENTIAL -- AICyberAuditBox Full Architectural Evaluation", align="C")

    def hline(self, color=MID_GRAY, thickness=0.3):
        self.set_draw_color(*color)
        self.set_line_width(thickness)
        y = self.get_y()
        self.line(10, y, 200, y)
        self.ln(3)

    def section_title(self, text):
        self.ln(4)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*DARK_TEXT)
        self.cell(0, 8, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.hline(ACCENT_BLUE, 0.5)

    def subsection_title(self, text):
        self.ln(2)
        self.set_font("Helvetica", "B", 10.5)
        self.set_text_color(*DARK_TEXT)
        self.cell(0, 6, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def body(self, text, size=10, color=BODY_TEXT, indent=0, bold=False):
        self.set_font("Helvetica", "B" if bold else "", size)
        self.set_text_color(*color)
        self.set_x(10 + indent)
        self.multi_cell(190 - indent, 5.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def draw_diagram_block(self, text):
        line_h = 4.5
        padding = 6  # top + bottom breathing room
        n_lines = text.count("\n") + 1
        needed_h = n_lines * line_h + padding

        # If the diagram won't fit on the remaining page, start a new one
        remaining = self.h - self.b_margin - self.get_y()
        if needed_h > remaining:
            self.add_page()

        self.set_fill_color(*LIGHT_GRAY)
        self.set_text_color(*DARK_TEXT)
        self.set_font("Courier", "", 8.5)
        self.set_x(10)
        self.multi_cell(190, line_h, text, fill=True, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)

def build_pdf():
    pdf = FullEvalPDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.set_margins(10, 14, 10)

    # ════════════════════════════════════════════
    # PAGE 1 -- Title & Exec Summary
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*DARK_TEXT)
    pdf.cell(0, 10, "Full Project Evaluation (EVL) Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    # Metadata info
    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(*BODY_TEXT)
    pdf.cell(0, 5, "Project Name: AICyberAuditBox - Local Audit", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 5, "Target Architecture: CPU-Only (8 Cores, 16GB RAM)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 5, "Inference Backend: Optimized llama.cpp (llama-server.exe)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 5, "Embedding Model: Nomic Embed Text v1.5 (nomic-embed-text-v1.5.f16.gguf)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 5, "Reranker Model: ms-marco-MiniLM-L-6-v2", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    import datetime
    pdf.cell(0, 5, f"Evaluation Date: {datetime.date.today().strftime('%B %d, %Y')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)
    pdf.hline(ACCENT_BLUE, 1.0)

    pdf.section_title("1. Executive Summary")
    exec_summary = (
        "This report evaluates the AICyberAuditBox compliance auditing system. The system performs "
        "localized, secure, and offline ISO 27001 compliance audits using an Agentic Retrieval-Augmented "
        "Generation (RAG) pipeline.\n\n"
        "This evaluation reviews the complete project architecture, details the token system configuration, "
        "explains how the system handles RAG text limiting/overflow, and documents the custom validator and "
        "self-correction mechanics built to guarantee compliance auditing accuracy on a resource-constrained "
        "CPU-only infrastructure."
    )
    pdf.body(exec_summary)

    # ════════════════════════════════════════════
    # PAGE 2 -- Architecture & Diagram 1
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("2. Core Project Architecture")
    pdf.body(
        "The AICyberAuditBox is designed for offline deployment with high data privacy. "
        "It operates on a modular C++/Python/SQL architecture:"
    )
    pdf.ln(2)
    pdf.draw_diagram_block(ARCH_DIAGRAM)
    
    pdf.subsection_title("Architectural Modules:")
    pdf.body("1. User Interface (Streamlit): Serves as the auditor dashboard. Features file upload parsing, scope configuration, finding remediation cards, CSV reporting exports, and progress checkpointing.", indent=4)
    pdf.ln(1)
    pdf.body("2. Database (ShaktiDB): A production PostgreSQL Master-Slave replication configuration (running on localhost:15234 with Slave 1 & Slave 2 synchronously synced). The app auto-switches to SQLite if PostgreSQL is unreachable.", indent=4)
    pdf.ln(1)
    pdf.body("3. Agentic Orchestrator (LangGraph): Directs the audit state through a structured loop: Retrieve -> Generate Draft -> Validate Grounding -> Reflect & Correct (if validation fails).", indent=4)

    # ════════════════════════════════════════════
    # PAGE 3 -- Scoping & Ingestion Pipeline (NEW CHRONOLOGICAL FLOW)
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("3. Zero-LLM Scoping & Custom Control Ingestion")
    pdf.body("To minimize processing latency and handle hundreds of controls without performance degradation, the system implements a local, high-speed scoping and custom control ingestion engine.")
    
    pdf.subsection_title("A. Zero-LLM Hybrid Scoping")
    pdf.body("o  Challenge: Brute-forcing 92 controls against 20 documents requires 1,840 LLM runs. Initial scoping via generative models takes ~20s per run and is prone to hallucination.", indent=4)
    pdf.body("o  Layer 1 (Python Keyword Signals): Scans for keywords/synonyms with strict word boundaries to prevent substring overlaps.", indent=4)
    pdf.body("o  Layer 2 (Semantic Embedding Match): Embeds the first 800 characters of the document and checks Cosine Similarity against all category definitions. Category match is scoped-in if similarity >= 0.645.", indent=4)
    pdf.body("o  Result: Bypasses generative LLM calls on upload, completing scoping checks in under 410 milliseconds and reducing the audit surface area by 90%.", indent=4)
    
    pdf.subsection_title("B. Custom Compliance Controls Ingestion Flow")
    pdf.body("Auditors can define custom controls directly through the UI or via Excel. The system processes and synchronizes these controls using a deterministic local pipeline:")
    pdf.ln(1)
    pdf.draw_diagram_block(CUSTOM_CONTROL_DIAGRAM)
    
    pdf.subsection_title("C. Local NLP & Cache Management Specs")
    pdf.body("o  Local Tokenization (Word Splitting): Normalizes name/description text and splits using regular expressions at spacing/punctuation boundaries, filtering stop-words.", indent=4)
    pdf.body("o  Deterministic Bigram Building: Constructs word-pairs (e.g. 'incident response') to ensure query matching precision.", indent=4)
    pdf.body("o  Synonym Map Expansion: Expands tokens to include synonyms (e.g. 'pii' expands to gdpr, privacy, data subject).", indent=4)
    pdf.body("o  Real-time Cache Sync: Saves the control to database. Invalidates UI session cache (_CUSTOM_UC_CACHE_TS = 0) to immediately refresh sidebar scope lists.", indent=4)

    # ════════════════════════════════════════════
    # PAGE 4 -- Token System & Context
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("4. Token System & Context Architecture")
    pdf.body("To ensure fast and stable execution on CPU-only hardware, the project implements a strict token management system:")
    
    pdf.subsection_title("A. Document Chunking Size (200-500 Tokens)")
    pdf.body("o  The parser splits documents into paragraphs based on double newlines (\\n\\n), filtering out blocks shorter than 40 characters.", indent=4)
    pdf.body("o  Oversized Paragraph Splitter: If any paragraph exceeds 800 characters (such as the list of incident phases in the Motorola plan), it is dynamically split by single newlines \\n before windowing. This prevents silent truncation of critical policy requirements.", indent=4)
    pdf.body("o  Chunks are created using a sliding window of 3 consecutive paragraphs with a stride of 1 paragraph (meaning Chunk 1 contains paragraphs 1-3, Chunk 2 contains paragraphs 2-4).", indent=4)
    pdf.body("o  Chunks have a hard cap (MAX_CHUNK_CHARS) of 2,000 characters (raised from 1,200) to ensure entire clauses are captured intact. A single chunk typically contains 200 to 500 tokens.", indent=4)

    pdf.subsection_title("B. Prompt Context Allocation")
    pdf.body("For every audit query, the input prompt consists of:")
    pdf.body("o  RAG Context Budget (1,800 to 2,200 Tokens): Up to 5 to 7 high-scoring text chunks retrieved from documents.", indent=4)
    pdf.body("o  RAG Bypass for Small Files: For policy documents under 35KB (approx. 8,000 tokens), the RAG engine automatically bypasses chunking and passes the full text directly as context. This guarantees 100% information coverage for small files.", indent=4)
    pdf.body("o  System Instructions (800 to 1,000 Tokens): Fixed rules, compliance definition schema, and formatting templates.", indent=4)
    pdf.body("o  Total Input Prompt Size: Around 2,600 to 3,200 tokens (or up to 6,000 tokens in full document bypass mode).", indent=4)

    pdf.subsection_title("C. Context Safety Buffer")
    pdf.body("o  The model's context window (num_ctx) is configured to 8,192 tokens (raised from 4,096 to prevent truncation of RAG payloads).", indent=4)
    pdf.body("o  Since the input prompt averages ~3,100 tokens (and maxes at ~6,000 in bypass mode), it leaves a generous safety buffer of 2,000 to 5,000 tokens for the LLM output.", indent=4)
    pdf.body("o  Because the final finding report generated by the LLM is only ~200 to 400 tokens, the system is mathematically guaranteed to fit within the memory limits without context crashes.", indent=4)

    pdf.subsection_title("D. Local AI Engine & Parameters Configuration")
    pdf.body("o  Large Language Model (LLM): google_gemma-4-E4B-it-Q4_K_M.gguf (Gemma 4B E4B Instruct model, Q4_K_M quantization). Hosted on 127.0.0.1:11434 with -c 8192 context window, -t 8 execution threads, -b 512 batch size, and --flash-attn on.", indent=4)
    pdf.body("o  Text Embedding Model: nomic-embed-text-v1.5.f16.gguf (Nomic Embed Text v1.5, f16 precision, 768 dimensions, native 8,192 token context, supports Matryoshka learning). Hosted on 127.0.0.1:11435 in --embedding server mode with -t 4 threads.", indent=4)
    pdf.body("o  Cross-Encoder Reranker Models: cross-encoder/ms-marco-MiniLM-L-6-v2 (Quick mode, ~80MB 6-layer MiniLM) and BAAI/bge-reranker-base (Deep mode, ~278MB high-precision base transformer). Reranker length is hard-capped at max_length=512. Toggled via dynamic lazy-loading and garbage collection (gc.collect()) to free memory and prevent CPU OOM crashes.", indent=4)
    pdf.body("o  Client-Side Parameters: temperature=0.0 (strictly deterministic), client-side num_ctx=4096 tokens, and keep_alive='15m' to prevent memory unloading between control runs.", indent=4)

    # ════════════════════════════════════════════
    # PAGE 5 -- Token Overflow & Diagram 2
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("5. Handling Token Overflow & Limiting Constraints")
    pdf.body("When processing large text databases (like 20 files simultaneously), the system implements several layers of protection against token limits and evidence omission:")

    pdf.subsection_title("A. Token Accumulation & Ranking")
    pdf.body("If a document contains 15 or 20 relevant paragraphs, the RAG engine avoids exceeding token budgets by sorting all retrieved chunks globally using a hybrid score (60% semantic vector + 40% keyword match) and accumulating them until it hits the 1,800 token budget limit (hard max 2,200 tokens).")

    pdf.subsection_title("B. Multi-Document Diversity Enforcement")
    pdf.body("To prevent a single document from dominating the token budget and hiding evidence in other files, the engine dynamically injects at least one chunk from each source file into the final selected chunks.")

    pdf.subsection_title("C. What if Critical Evidence is Left Out?")
    pdf.body("If the RAG engine limits the context and leaves out a paragraph containing the compliance evidence, the system prevents false passes through a multi-stage validation loop:")
    pdf.ln(2)
    pdf.draw_diagram_block(SEQ_DIAGRAM)

    # ════════════════════════════════════════════
    # PAGE 6 -- Shifting, Truncation & KV Cache
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.body("1. Grounding Validator Gate: The custom validator (validator.py) scans the SQL database. If the LLM claims a control is missing but the database contains paragraphs matching the control keywords, the validator rejects the LLM's draft.", indent=4)
    pdf.ln(1)
    pdf.body("2. Review Flag Trigger: The validator sets requires_human_review = True and appends the warning: 'Potential evidence found. Human verification needed.'", indent=4)
    pdf.ln(1)
    pdf.body("3. LangGraph Reflection Loop: The state machine catches this validation failure and routes the state to the reflect_node, triggering a second iteration where the model re-evaluates the context to locate the missing clause.", indent=4)
    pdf.ln(2)

    pdf.subsection_title("D. Native llama.cpp Context Resets (Shifting)")
    pdf.body("If the combined prompt size ever exceeds the limit, the C++ backend manages memory via Context Shifting: it keeps the system prompt intact, discards the oldest prompt evaluation states in the KV-Cache, and shifts the sliding context window forward.")

    pdf.subsection_title("E. Silent Ingestion Truncation Bug Resolved")
    pdf.body("o  The Bug: Paragraphs lacking blank lines were grouped into a single block. If this block exceeded the hard limit (MAX_CHUNK_CHARS of 1,200 chars), the parser split the chunk and permanently discarded the remainder of the text. This caused entire sections (such as Section 3.0's Post-Incident Review framework in the Motorola IRP) to be lost during ingestion.", indent=4)
    pdf.body("o  The Resolution: Implemented a dynamic splitter (paragraphs > 800 chars split by single newlines \\n), raised chunk cap to 2,000 characters, enabled small document RAG bypass (<35KB), and configured validator.py to check full document text as a fallback.", indent=4)

    pdf.subsection_title("F. KV-Cache Prefix Reuse for Multi-Control Speedups")
    pdf.body("o  Mechanic: The llama-server.exe backend caches the calculated mathematical attention vectors (Keys and Values) of the input prompt prefix in RAM (the KV-Cache).", indent=4)
    pdf.body("o  Optimization & Results: For subsequent controls, the server bypasses the heavy CPU prefill calculations entirely, loading the KV-cache instantly. In our audit benchmark, the first control (5.24) took 8.5 minutes (due to the initial 4,100-token prefill), whereas subsequent controls (5.25, 5.26, etc.) bypassed the prefill and finished in only 1.8 minutes (a 5x speedup).", indent=4)

    # ════════════════════════════════════════════
    # PAGE 7 -- Validator & Benchmarking
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("6. RAG & Custom Validator Pipeline Evaluation")
    pdf.body("The custom forensic validator performs strict checks to prevent prompt leaks and hallucinations:")
    pdf.body("o  Gate 1 (Prompt Leakage): Blocks prompt templates and expected guidelines from leaking into output citations.", indent=4)
    pdf.body("o  Gate 2 (Verbatim Grounding): Direct lookup checks to ensure LLM quotes exist word-for-word in the source document.", indent=4)
    pdf.body("o  Gate 3 (Fuzzy OCR Grounding): Sequence matching fallback (similarity threshold >= 85%) for scanned PDF/image OCR data.", indent=4)
    pdf.body("o  Gate 4 (Consistency): Overrides LLM output to NON_COMPLIANT if the model claims compliance but lists zero verified evidence quotes.", indent=4)

    pdf.subsection_title("G. Quick Audit vs. Deep Audit Execution Pathways")
    pdf.body("The system runs in two operational modes depending on accuracy and latency needs:")
    pdf.body("o  Quick Audit (Single-Pass Mode): The LLM evaluates the context once. If the grounding validator rejects the draft, the orchestrator immediately accepts the validator's overrides (such as status downgrades or human review flags) and proceeds.", indent=4)
    pdf.body("o  Deep Audit (Multi-Pass Self-Correction Mode): If validation fails, the orchestrator enters a self-correction loop managed by LangGraph. It queries the model again, providing detailed feedback of the failed verification (for up to 2 retries).", indent=4)
    pdf.ln(2)
    pdf.draw_diagram_block(QUICK_DEEP_DIAGRAM)

    # ════════════════════════════════════════════
    # PAGE 8 -- CPU Performance & Benchmarking
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("7. Performance Benchmarking & CPU Optimization")
    pdf.body("To accommodate the CPU-only client requirement, we tuned the server parameters to achieve optimal execution:")
    pdf.body("o  Thread Tuning (-t 8): Set LLM threads to match your 8 physical cores to maximize core saturation.", indent=4)
    pdf.body("o  Batch Processing (-b 512): Enabled prompt evaluation chunking to speed up CPU prefill ingestion.", indent=4)
    pdf.body("o  RAM Optimization: Removed --mlock to allow the OS to dynamically page memory, freeing up RAM for PostgreSQL and Streamlit.", indent=4)
    pdf.body("o  Robust Parsing Fallback: Enhanced the XML regex parser in audit_chains.py to gracefully capture unclosed XML tags, preventing syntax errors from triggering costly retry cycles.", indent=4)
    pdf.ln(3)

    pdf.subsection_title("Real-World Audit Speedup (Control 5.15):")
    pdf.body("o  Before Optimization: 716.83 seconds (~12.0 minutes)", indent=4)
    pdf.body("o  After Optimization: 500.71 seconds (~8.3 minutes)", indent=4)
    pdf.body("o  Total Savings: 216.12 seconds (~3.6 minutes saved per control - a 30.15% speedup!)", indent=4)

    # ════════════════════════════════════════════
    # PAGE 9 -- VAPT Engine & Lifecycle Flow
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("8. VAPT Ingestion & Reporting Engine")
    pdf.body("To support technical audits alongside compliance checking, the system implements a dedicated VAPT (Vulnerability Assessment & Penetration Testing) subsystem. This allows the system to ingest raw security logs and cross-walk technical vulnerabilities directly to compliance standards.")
    
    pdf.subsection_title("A. The VAPT Audit Pipeline Lifecycle")
    pdf.body("The step-by-step lifecycle of a VAPT audit execution follows a structured pipeline:")
    pdf.ln(1)
    pdf.draw_diagram_block(VAPT_DIAGRAM)

    # ════════════════════════════════════════════
    # PAGE 9.5 -- Multi-Scanner Log Parsers & CVSS Mapping
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.subsection_title("B. Multi-Scanner Log Parsers")
    pdf.body("The system features structured regex and heuristic log parsers that ingest and normalize raw output files from standard security scanning tools:")
    pdf.body("o  Nmap Infrastructure Scan: Analyzes port states, service version strings, and SSL/TLS cipher suites (specifically parsing out CBC-based suites vulnerable to Lucky13 attacks).", indent=4)
    pdf.body("o  Nessus Vulnerability Report: Extracts active vulnerabilities, port bindings, severity classifications, and recommendations.", indent=4)
    pdf.body("o  Burp Suite Web Application Scan: Parses web application issues (like missing Secure/HttpOnly flags on session cookies or missing headers).", indent=4)
    pdf.body("o  Legacy MS Word/Manual Pentesting Reports: Ingests unstructured manual reports, using sentence tokenization and semantic filtering to extract and structure manual findings.", indent=4)
    
    pdf.subsection_title("C. Dynamic CVSS v4.0 Metric Mapping")
    pdf.body("Different scanners report risk severity using conflicting systems (grades, letter scores, text classifications). The auditor engine harmonizes this by translating all findings to the standard CVSS v4.0 framework:")
    pdf.body("o  Network-Level Scan Metrics: For infrastructure vulnerabilities (like weak ciphers), the system sets Attack Vector (AV) to 'Network' and User Interaction (UI) to 'None', which yields high exploitability ratings.", indent=4)
    pdf.body("o  Web-Application Metrics: For application weaknesses (like missing secure cookie flags), the system adjusts User Interaction (UI) to 'Required' and Privileges Required (PR) to 'None'/'Low' depending on the session context.", indent=4)
    pdf.body("o  Impact Vectors: Dynamically maps system impact metrics-Confidentiality (VC), Integrity (VI), and Availability (VA)-to compute the overall CVSS v4.0 base score.", indent=4)

    # ════════════════════════════════════════════
    # PAGE 10 -- VAPT Controls Checklist
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.subsection_title("D. VAPT Framework Controls Checklist (VAPT-1 to VAPT-15)")
    pdf.body("The system cross-walks parsed scan findings against the 15 VAPT controls:")
    pdf.ln(2)
    
    hdr_style_evl = FontFace(emphasis="B", color=(255, 255, 255), fill_color=(15, 23, 42))
    lbl_style_evl = FontFace(emphasis="B", fill_color=(245, 247, 250))
    with pdf.table(col_widths=(20, 60, 100), text_align="L") as table:
        h = table.row()
        h.cell("Control ID", style=hdr_style_evl)
        h.cell("Control Name", style=hdr_style_evl)
        h.cell("Focus & Description", style=hdr_style_evl)
        
        controls = [
            ("VAPT-1", "Rules of Engagement", "Verifies IP ranges, scope exclusions, and timelines."),
            ("VAPT-2", "OSINT Reconnaissance", "Audits domain leaks, active hosts, and open intelligence."),
            ("VAPT-3", "Network Vulnerability Scan", "Open ports, service versions, weak TLS ciphers (Lucky13)."),
            ("VAPT-4", "Web Application OWASP 10", "Cookies (HttpOnly/Secure), XSS, injection flaws, headers."),
            ("VAPT-5", "Internal Pentesting", "Lateral movement, unauthenticated Redis, DB exposure."),
            ("VAPT-6", "External Pentesting", "Edge systems, public gateway exposures."),
            ("VAPT-7", "Privilege Escalation", "Access levels, sudo config, service exploit paths."),
            ("VAPT-8", "Social Engineering", "Phishing campaign statistics, user awareness training."),
            ("VAPT-9", "Wireless Security", "WPA3 Enterprise, guest network isolation, rogue APs."),
            ("VAPT-10", "API Security", "REST/SOAP API auth keys, input validations."),
            ("VAPT-11", "Remediation Tracking", "Vulnerability tracking, ticketing integrations, SLAs."),
            ("VAPT-12", "Patch Verification", "Outdated software version detection and patch verification."),
            ("VAPT-13", "Firewall & Segment Review", "VLAN boundaries, firewall rule base, ACL lists."),
            ("VAPT-14", "Secure Baseline Config", "Disabled defaults, default credential audits, cipher audits."),
            ("VAPT-15", "Final Regulatory Report", "Registered offices details, submission tables, overall CVSS.")
        ]
        for cid, cname, cdesc in controls:
            r = table.row()
            r.cell(cid, style=lbl_style_evl)
            r.cell(cname)
            r.cell(cdesc)

    # ════════════════════════════════════════════
    # PAGE 11 -- Grounding & Output Format
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.subsection_title("E. VAPT 4-Gate Grounding & Hallucination Prevention")
    pdf.body("Because vulnerability details are highly sensitive to alphanumeric accuracy (matching IP addresses or version tags), the custom validator enforces strict grounding rules:")
    pdf.body("o  Gate 1 (Verbatim IP and Port Grounding): LLM draft findings must cite IP addresses and port numbers that exist word-for-word in the source document chunks.", indent=4)
    pdf.body("o  Gate 2 (Scant Version Matching): Verifies service versions (e.g. Apache httpd 2.4.38) match the logs exactly, preventing the AI from hallucinating hypothetical versions.", indent=4)
    pdf.body("o  Gate 3 (Smart Override & Warnings): If a scan finding is identified in logs but skipped by the LLM, the validator automatically overrides and flags it as NON_COMPLIANT for human review.", indent=4)
    pdf.body("o  Gate 4 (Consistency Check): Automatically rejects and re-runs drafts that claim a control is compliant but contain zero verified evidence quotes.", indent=4)
    
    pdf.subsection_title("F. TÜV SÜD Template Replication (Dual-Format)")
    pdf.body("The system compiles these parsed findings into reports matching the exact layout of the official TÜV SÜD South Asia registration template. It outputs both formats:")
    pdf.body("o  Official PDF (_export_vapt_pdf): A print-ready document containing cover pages, Document Version Control and Document Submission Details tables, a Vulnerabilities Summary table, and a detailed findings grid with CVSS v4.0 metrics, Proof of Concept, and remediation references.", indent=4)
    pdf.body("o  Remediation DOCX (_export_vapt_docx): A fully editable Word document replication. This is critical for security operations teams to copy-paste remediation commands, add internal ticket tracking, or edit recommendations before final regulatory submission.", indent=4)

    # ════════════════════════════════════════════
    # OUTPUT PDF
    # ════════════════════════════════════════════
    pdf.output(OUTPUT_PATH)
    print(f"Full Evaluation PDF saved to: {os.path.abspath(OUTPUT_PATH)}")

if __name__ == "__main__":
    build_pdf()
