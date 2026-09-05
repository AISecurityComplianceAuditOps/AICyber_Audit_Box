"""
generate_multi_doc_pdf.py
Generates a professional white-template PDF version of the MULTI_DOCUMENT_AUDIT_GUIDE.md report.
Run: python scripts/generate_multi_doc_pdf.py
"""

from fpdf import FPDF
from fpdf.enums import XPos, YPos
import os, re

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "MULTI_DOCUMENT_AUDIT_GUIDE.pdf")
MD_PATH = os.path.join(os.path.dirname(__file__), "..", "MULTI_DOCUMENT_AUDIT_GUIDE.md")

# ── Colour Palette ──────────────────────────────────────────────────────────
DARK_BG      = (15,  23,  42)
ACCENT_BLUE  = (59, 130, 246)
LIGHT_GRAY   = (245, 247, 250)
DARK_TEXT    = (15,  23,  42)
BODY_TEXT    = (51,  65,  85)
WHITE        = (255, 255, 255)
MID_GRAY     = (180, 180, 180)

# ── ASCII Diagrams ──────────────────────────────────────────────────────────
RAG_DIAGRAM = """
                +-------------------------------------------+
                |   Hybrid Search (Vector + BM25 Keyword)   |
                +-------------------------------------------+
                                      |
                                      v
                +-------------------------------------------+
                |   Global Relevance Ranking (All Chunks)   |
                +-------------------------------------------+
                                      |
                                      v
                +-------------------------------------------+
                |   Multi-Document Diversity Enforcement    |
                | (Guarantees at least 1 chunk per document)|
                +-------------------------------------------+
                                      |
                                      v
                +-------------------------------------------+
                |      Final Selected Prompt Context        |
                +-------------------------------------------+
"""

VALIDATOR_DIAGRAM = """
  +------------------+         +---------------------+         +----------------------+
  |  Combined Files  |         |    LLM Generator    |         |  Grounding Validator |
  +------------------+         +---------------------+         +----------------------+
           |                              |                               |
           | --- Sends Context Prompt --> |                               |
           |                              | --- Draft Report -----------> |
           |                              |     (Status: NON_COMPLIANT    |
           |                              |      Evidence: NOT_FOUND)     |
           |                              |                               | -- Scans ALL chunks
           |                              |                               |    for ALL files in DB
           |                              |                               |
           |                              | <--- Keywords exist in C ---- | (Evidence in File C)
           |                              |                               |
           |                              | === Validation REJECTED! ===  |
           |                              | === Override to PARTIAL ====  |
           |                              | --- Flags Human Review -----> |
           v                              v                               v
"""

class MultiDocPDF(FPDF):
    def header(self):
        self.set_draw_color(*MID_GRAY)
        self.set_line_width(0.2)
        self.line(10, 8, 200, 8)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*MID_GRAY)
        self.set_xy(10, 3)
        self.cell(0, 5, "AICyberAuditBox  --  Multi-Document Audit Guide (Quick Audit)", align="L")
        self.set_xy(0, 3)
        self.cell(200, 5, f"Page {self.page_no()}", align="R")
        self.ln(10)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*MID_GRAY)
        self.cell(0, 6, "CONFIDENTIAL -- AICyberAuditBox Pipeline Guide", align="C")

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
        self.set_fill_color(*LIGHT_GRAY)
        self.set_text_color(*DARK_TEXT)
        self.set_font("Courier", "", 8.5)
        self.set_x(10)
        self.multi_cell(190, 4.5, text, fill=True, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)

def clean_md_styling(text):
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)
    text = re.sub(r'(?<!\*)\*([^*]+)\*(?!\*)', r'\1', text)
    text = text.replace("—", "-").replace("–", "-")
    text = text.replace("’", "'").replace("‘", "'")
    text = text.replace("“", '"').replace("”", '"')
    text = text.replace("…", "...").replace("➔", "->")
    text = text.replace("📋", "")
    return text.strip()

def build_pdf():
    if not os.path.exists(MD_PATH):
        print(f"Error: Markdown file not found at {MD_PATH}")
        return

    pdf = MultiDocPDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.set_margins(10, 14, 10)

    # ════════════════════════════════════════════
    # PAGE 1 -- Title & Section 1
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*DARK_TEXT)
    pdf.cell(0, 10, "Multi-Document Audit Guide (Quick Audit)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    # Metadata info
    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(*BODY_TEXT)
    pdf.cell(0, 5, "Project Name: AICyberAuditBox - Local Audit", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 5, "Capability: Multi-Document Processing, RAG Retrieval, and Validation", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 5, "Report Date: July 7, 2026", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)
    pdf.hline(ACCENT_BLUE, 1.0)

    pdf.section_title("1. Overview")
    pdf.body(
        "When performing compliance audits, security policies and evidence are rarely contained within a single file. "
        "Auditors often need to upload a package of documents (e.g., standard operating procedures, asset registers, "
        "and configuration screenshots).\n\n"
        "This guide explains the pipeline mechanics of how the AICyberAuditBox processes, retrieves, evaluates, "
        "and validates compliance across multiple uploaded documents simultaneously during a Quick Audit run."
    )

    pdf.subsection_title("1.1 Why Not Document-by-Document? (The Fragmentation Problem)")
    pdf.body("In standard compliance auditing, evidence is often distributed across separate files:")
    pdf.body("o  High-Level Policy (Doc A): Says 'MSI must have an incident plan.'", indent=4)
    pdf.body("o  Response Runbook (Doc B): Outlines the 6 phases of an incident.", indent=4)
    pdf.body("o  Roles Matrix (Doc C): Lists the names and contact info of the response team.", indent=4)
    pdf.ln(1)
    pdf.body("If the system audited each document separately, it would produce three fragmented and incorrect results: Doc A alone returns PARTIAL_COMPLIANT (missing operational phases and team roles); Doc B alone returns NON_COMPLIANT (missing policy statements and team roles); and Doc C alone returns NON_COMPLIANT (unstructured roster with no context).")
    pdf.ln(1)
    pdf.body("The Solution: Instead of looping control-by-control for each document, the RAG engine aggregates context from all uploaded documents simultaneously. The LLM receives a consolidated view of the entire package, enabling a single, unified, and highly accurate compliance status for each control.")

    pdf.section_title("2. Ingestion & Database Stage")
    pdf.body("Every uploaded file - regardless of format - goes through a specialized parser and is stored in the database:")
    pdf.body("o  File Type Parsing: The Streamlit dashboard parses files based on format (PDF, DOCX, XLSX, CSV, PPTX, Images).", indent=4)
    pdf.body("o  Unified Database Indexing: All parsed chunks are stored in a single unified table (DocumentChunk in ShaktiDB).", indent=4)
    pdf.body("o  Metadata Tagging: Each database record is tagged with its source file's filename and page_number / row_index so that citations can be mapped back to their origin.", indent=4)

    # ════════════════════════════════════════════
    # PAGE 2 -- RAG & Diagram 1
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("3. Retrieval & Diversity Enforcement (RAG)")
    pdf.body("When auditing a specific control, the RAG engine queries all chunks associated with the uploaded files:")
    pdf.ln(2)
    pdf.draw_diagram_block(RAG_DIAGRAM)

    pdf.body("1. Global Ranking: Chunks from all files are fetched and ranked together using a hybrid score (60% semantic similarity + 40% keyword match).", indent=4)
    pdf.ln(1)
    pdf.body("2. Evidence Diversity Enforcement: To prevent a single long policy document from dominating the context budget and hiding evidence in secondary files, the RAG engine enforces diversity. It ensures that at least one relevant chunk from each uploaded file is injected into the final context, even if its raw score was slightly lower than other chunks.", indent=4)

    pdf.section_title("4. Context Size Decision")
    pdf.body("To optimize CPU performance and memory consumption, the system makes a threshold-based choice:")
    pdf.body("o  Small Combined Size (< 35KB / ~8,000 tokens): Bypasses chunking entirely and sends the entire combined text of all documents to the LLM. This guarantees 100% information coverage.", indent=4)
    pdf.body("o  Large Combined Size (>= 35KB / ~8,000 tokens): Selects only the globally ranked chunks (including the diversity chunks) up to a max budget of 1,800 to 2,200 tokens to prevent context window crashes.", indent=4)

    # ════════════════════════════════════════════
    # PAGE 3 -- Validator & Diagram 2
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("5. Quick Audit Evaluation & Validation Gate")
    pdf.body("In a Quick Audit, the orchestrator evaluates the prompt context in a single pass:")
    pdf.ln(2)
    pdf.draw_diagram_block(VALIDATOR_DIAGRAM)

    pdf.body("1. LLM Evaluation (Single-Pass): The LLM reviews the context once and generates its draft compliance status, cited evidence, and gaps. Because it is Quick Mode, no self-correction retries are performed.", indent=4)
    pdf.ln(1)
    pdf.body("2. Validator Verbatim Check: The custom validator scans the database to ensure the LLM's cited quote exists word-for-word in at least one of the uploaded files.", indent=4)
    pdf.ln(1)
    pdf.body("3. Smart Validator Override: If the LLM output is 'NOT_FOUND' (because the evidence chunk did not fit in the RAG budget), the validator runs a keyword scan (potential_evidence_exists()) across the database chunks of all uploaded files. If matching keywords are found in any file, the validator automatically overrides the LLM's draft, upgrading status to PARTIAL_COMPLIANT, flagging requires_human_review = True, and setting grounded check to False.", indent=4)

    pdf.output(OUTPUT_PATH)
    print(f"Multi-Doc Guide PDF saved to: {os.path.abspath(OUTPUT_PATH)}")

if __name__ == "__main__":
    build_pdf()
