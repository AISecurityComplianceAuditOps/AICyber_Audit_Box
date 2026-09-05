# -*- coding: utf-8 -*-
from fpdf import FPDF
from fpdf.enums import XPos, YPos
import os
import sys

class ShaktiDBPDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 8)
        self.set_text_color(100, 116, 139)
        self.cell(0, 8, 'AICyberAuditBox - ShaktiDB (IITM Pravartak) Enterprise Report', align='R', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(226, 232, 240)
        self.line(15, 18, 195, 18)
        self.ln(4)
        
    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', '', 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 8, f'Page {self.page_no()}', align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

def clean(text):
    if not text:
        return ""
    text = str(text).replace('—', '-').replace('–', '-').replace('•', '*').replace('’', "'").replace('“', '"').replace('”', '"')
    text = text.encode('latin-1', 'replace').decode('latin-1')
    return text

def build_pdf():
    pdf = ShaktiDBPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()

    # Title Block
    pdf.set_font('Helvetica', 'B', 15)
    pdf.set_text_color(15, 23, 42)
    pdf.multi_cell(180, 7, clean("ShaktiDB (IITM Pravartak) Enterprise Feature & Version Comparison Report"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.set_font('Helvetica', 'I', 9.5)
    pdf.set_text_color(71, 85, 105)
    pdf.multi_cell(180, 5, clean("Sovereign Database Infrastructure, Regulatory Compliance & AICyberAuditBox Integration Analysis"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    # Divider Line
    pdf.set_draw_color(203, 213, 225)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(4)

    # Section 1: Executive Overview
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 6, clean("1. Executive Overview & Sovereign Infrastructure"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    pdf.set_font('Helvetica', '', 8.5)
    pdf.set_text_color(51, 65, 85)
    overview_text = [
        "ShaktiDB is an indigenously developed, enterprise-grade relational database system built on PostgreSQL by IITM Pravartak Technologies Foundation (hosted at IIT Madras) in collaboration with C-DAC.",
        "It is designed to provide secure, scalable, and sovereign database infrastructure specifically aligned with Indian regulatory frameworks including RBI, CERT-In (SBOM), CCRA, MeitY, and the DPDP Act.",
        "Engineered for mission-critical enterprise workloads, ShaktiDB combines PostgreSQL compatibility with enhanced security, native multi-factor authentication (MFA), and specialized audit tooling."
    ]
    for p in overview_text:
        pdf.multi_cell(180, 4.5, clean(p), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)
    pdf.ln(2)

    # Section 2: Version Release History Table
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 6, clean("2. ShaktiDB Version Release History & Evolution"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1.5)

    # Table Header
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(241, 245, 249)
    pdf.set_draw_color(203, 213, 225)
    
    col_widths = [26, 24, 25, 105]
    headers = ["Version", "Release Date", "Base Engine", "Key Highlights & Feature Additions"]
    
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 6, clean(h), border=1, align='L' if i==3 else 'C', fill=True)
    pdf.ln(6)

    pdf.set_font('Helvetica', '', 7.5)
    releases = [
        ("v17.10.1.0 (Latest)", "May 23, 2026", "PostgreSQL 17.10", "Maintenance release focusing on query planner stability, security fixes, memory optimization, and pgvector performance enhancements."),
        ("v17.7.1.1", "Apr 15, 2026", "PostgreSQL 17.7", "Optimized Debian build configuration resolving high-concurrency throughput bottlenecks under heavy parallel workloads."),
        ("v17.7.1.0", "Feb 27, 2026", "PostgreSQL 17.7", "Introduced Multi-Factor Authentication (MFA), sdb_cron job scheduler, sdbAudit tamper-evident logging, and sdbpool connection pooling."),
        ("v17.4.0.4", "Sep 29, 2025", "PostgreSQL 17.4", "Default SSL/TLS encryption, distributed multi-node replication support, and enhanced role-based access control (RBAC)."),
        ("v17.4.0.3", "Jun 07, 2025", "PostgreSQL 17.4", "Initial release based on PG 17; integrated OAuth2 / OIDC authentication for single sign-on enterprise logins.")
    ]

    for ver, date, base, desc in releases:
        pdf.cell(col_widths[0], 10, clean(ver), border=1, align='C')
        pdf.cell(col_widths[1], 10, clean(date), border=1, align='C')
        pdf.cell(col_widths[2], 10, clean(base), border=1, align='C')
        
        # Description cell multi_cell handling
        curr_x = pdf.get_x()
        curr_y = pdf.get_y()
        pdf.multi_cell(col_widths[3], 4.5, clean(desc), border=1, align='L')
        pdf.set_xy(curr_x + col_widths[3], curr_y + 10)
        pdf.ln(0)
    
    pdf.set_y(pdf.get_y() + 4)

    # Section 3: ShaktiDB vs Standard PostgreSQL Comparison
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 6, clean("3. Feature Comparison: ShaktiDB vs Standard PostgreSQL"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1.5)

    comp_widths = [35, 72, 73]
    comp_headers = ["Feature Category", "ShaktiDB (IITM Pravartak)", "Standard Open-Source PostgreSQL"]

    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(241, 245, 249)
    for i, ch in enumerate(comp_headers):
        pdf.cell(comp_widths[i], 6, clean(ch), border=1, align='C', fill=True)
    pdf.ln(6)

    pdf.set_font('Helvetica', '', 7.5)
    comparisons = [
        ("Regulatory Compliance", "Built-in alignment with RBI, CERT-In (SBOM), CCRA, and DPDP Act standards.", "Requires custom external modules, policies, and manual configurations."),
        ("Audit Logging", "Native sdbAudit for tamper-evident, non-repudiable audit logging.", "Requires installation of third-party plugins (e.g. pgaudit)."),
        ("Security Defaults", "Enforced SSL/TLS by default, native MFA, and OAuth2/OIDC integration.", "Default connections plain text; SSL and MFA require manual middleware."),
        ("Enterprise Tooling", "Bundled sdbpool (pooling), sdb_cron (scheduling), and sdbAdmin (UMC console).", "Relies on fragmented third-party tools (pgBouncer, pgAdmin, OS cron)."),
        ("Sovereignty", "100% Indian sovereign tech stack (IIT Madras Pravartak + C-DAC).", "Community-maintained international open-source software.")
    ]

    for cat, shakti, pg in comparisons:
        curr_y = pdf.get_y()
        pdf.cell(comp_widths[0], 10, clean(cat), border=1, align='C')
        
        pdf.multi_cell(comp_widths[1], 4.5, clean(shakti), border=1, align='L')
        pdf.set_xy(15 + comp_widths[0] + comp_widths[1], curr_y)
        
        pdf.multi_cell(comp_widths[2], 4.5, clean(pg), border=1, align='L')
        pdf.set_xy(15, curr_y + 10)
    
    pdf.ln(4)

    # Section 4: Project Integration
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 6, clean("4. How ShaktiDB Architecture Empowers AICyberAuditBox"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    pdf.set_font('Helvetica', '', 8.5)
    pdf.set_text_color(51, 65, 85)
    integrations = [
        "1. Master-Slave High Availability: The project utilizes a 3-engine cluster topology (shakthidb_master, slave1, slave2) for read load-balancing and instant failover promotion if the master write engine fails.",
        "2. Non-blocking Async Replication: Replication uses row-level DELETE FROM instead of TRUNCATE CASCADE, avoiding AccessExclusiveLock deadlocks on active reader transactions during background sync.",
        "3. Native pgvector RAG Indexing: Embeddings for security evidence documents are stored in 768-dimensional pgvector HNSW indexes (m=16, ef_construction=64) for sub-millisecond context retrieval.",
        "4. Automatic SQLite Resilience: If PostgreSQL/ShaktiDB is offline, the app seamlessly auto-switches to shakthidb_sqlite.db without server downtime or crash.",
        "5. Compliance Evidence Logging: Native sdbAudit logging maps directly to ISO 27001 & VAPT audit event history (SystemEvent & AdminAuditLog tables)."
    ]

    for item in integrations:
        pdf.multi_cell(180, 4.5, clean(item), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

    output_path = os.path.join(os.getcwd(), "ShaktiDB_IIT_Pravartak_Features_Report.pdf")
    pdf.output(output_path)
    print(f"PDF successfully generated at: {output_path}")
    return output_path

if __name__ == "__main__":
    build_pdf()
