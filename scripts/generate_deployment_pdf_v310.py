# -*- coding: utf-8 -*-
"""
Generate DEPLOYMENT_GUIDE_v3.10.pdf and AICyberAuditBox_Rolling_Update_Playbook_v3.10.pdf
Using ReportLab.
"""
import os
import re
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, Preformatted, PageBreak, KeepTogether
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(2 * cm, 28.2 * cm, "AICyberAuditBox v3.10 — Customer Deployment & Rolling Update Guide")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(2 * cm, 28.0 * cm, 19 * cm, 28.0 * cm)
            
        # Footer
        footer_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(19 * cm, 1.2 * cm, footer_text)
        self.drawString(2 * cm, 1.2 * cm, "CONFIDENTIAL — AICyberAuditBox Release Engineering")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(2 * cm, 1.6 * cm, 19 * cm, 1.6 * cm)
        
        self.restoreState()

def build_pdf(md_filename, pdf_filename, doc_title):
    with open(md_filename, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    doc = SimpleDocTemplate(
        pdf_filename, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.2*cm, bottomMargin=2.2*cm
    )

    styles = getSampleStyleSheet()

    S = {
        "title": ParagraphStyle("DocTitle", parent=styles["Heading1"], fontSize=22, leading=26, textColor=colors.HexColor("#0F172A"), spaceAfter=12, fontName="Helvetica-Bold"),
        "subtitle": ParagraphStyle("DocSubTitle", parent=styles["Normal"], fontSize=11, leading=15, textColor=colors.HexColor("#475569"), spaceAfter=16),
        "h1": ParagraphStyle("H1", parent=styles["Heading1"], fontSize=15, leading=19, textColor=colors.HexColor("#1E3A8A"), spaceBefore=14, spaceAfter=8, fontName="Helvetica-Bold", keepWithNext=True),
        "h2": ParagraphStyle("H2", parent=styles["Heading2"], fontSize=12, leading=16, textColor=colors.HexColor("#0F766E"), spaceBefore=10, spaceAfter=6, fontName="Helvetica-Bold", keepWithNext=True),
        "h3": ParagraphStyle("H3", parent=styles["Heading3"], fontSize=10.5, leading=14, textColor=colors.HexColor("#334155"), spaceBefore=8, spaceAfter=4, fontName="Helvetica-Bold", keepWithNext=True),
        "body": ParagraphStyle("BodyTextCustom", parent=styles["Normal"], fontSize=9.5, leading=14, textColor=colors.HexColor("#1E293B"), spaceAfter=6),
        "bullet": ParagraphStyle("BulletCustom", parent=styles["Normal"], fontSize=9.5, leading=14, textColor=colors.HexColor("#1E293B"), leftIndent=15, spaceAfter=4),
        "code": ParagraphStyle("CodeCustom", parent=styles["Code"], fontSize=8, leading=11, fontName="Courier", textColor=colors.HexColor("#0F172A"), backColor=colors.HexColor("#F1F5F9"), leftIndent=10, rightIndent=10, spaceBefore=4, spaceAfter=8),
        "callout": ParagraphStyle("CalloutCustom", parent=styles["Normal"], fontSize=9, leading=13, textColor=colors.HexColor("#1E293B"), backColor=colors.HexColor("#EFF6FF"), leftIndent=10, rightIndent=10, spaceBefore=6, spaceAfter=8),
    }

    story = []

    # Title Banner
    story.append(Paragraph(doc_title, S["title"]))
    story.append(Paragraph("Release Engineering & Air-Gapped Operation Manual • Version 3.10", S["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=14))

    def escape(t):
        return (t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                 .replace("→", "&#8594;").replace("—", "&#8212;").replace("–", "&#8211;")
                 .replace("✅", "OK ").replace("🎉", ""))

    def inline_fmt(t):
        t = escape(t)
        t = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', t)
        t = re.sub(r'`([^`]+)`', r'<font name="Courier" size="8.5" color="#0969DA"><b>\1</b></font>', t)
        return t

    lines = content.splitlines()
    i = 0
    in_code = False
    code_buf = []
    table_rows = []

    while i < len(lines):
        line = lines[i]

        # Code block handling
        if line.strip().startswith("```"):
            if not in_code:
                in_code = True
                code_buf = []
            else:
                in_code = False
                code_str = "\n".join(code_buf)
                story.append(Preformatted(code_str, S["code"]))
                story.append(Spacer(1, 4))
            i += 1
            continue

        if in_code:
            code_buf.append(line)
            i += 1
            continue

        # Table handling
        if line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(re.match(r"^[-:]+$", c) for c in cells if c):
                i += 1
                continue
            table_rows.append(cells)
            i += 1
            if i < len(lines) and lines[i].strip().startswith("|"):
                continue
            if table_rows:
                col_count = max(len(r) for r in table_rows)
                formatted_data = []
                for row_idx, r in enumerate(table_rows):
                    row_cells = []
                    for c in r:
                        if row_idx == 0:
                            p = Paragraph(f"<b>{inline_fmt(c)}</b>", ParagraphStyle("TH", parent=S["body"], fontSize=8.5, leading=11, textColor=colors.white))
                        else:
                            p = Paragraph(inline_fmt(c), ParagraphStyle("TD", parent=S["body"], fontSize=8.5, leading=11))
                        row_cells.append(p)
                    while len(row_cells) < col_count:
                        row_cells.append(Paragraph("", S["body"]))
                    formatted_data.append(row_cells)
                
                # Render Table
                t = Table(formatted_data, hAlign="LEFT")
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E3A8A")),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
                    ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#94A3B8")),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ]))
                story.append(t)
                story.append(Spacer(1, 8))
                table_rows = []
            continue

        raw = line.strip()
        if not raw:
            i += 1
            continue

        # Headings
        if raw.startswith("# "):
            story.append(Paragraph(inline_fmt(raw[2:]), S["h1"]))
        elif raw.startswith("## "):
            story.append(Paragraph(inline_fmt(raw[3:]), S["h2"]))
        elif raw.startswith("### "):
            story.append(Paragraph(inline_fmt(raw[4:]), S["h3"]))
        elif raw.startswith("- ") or raw.startswith("* "):
            story.append(Paragraph(f"• {inline_fmt(raw[2:])}", S["bullet"]))
        elif re.match(r"^\d+\.\s+", raw):
            item_text = re.sub(r"^\d+\.\s+", "", raw)
            story.append(Paragraph(f"<b>{raw.split('.')[0]}.</b> {inline_fmt(item_text)}", S["bullet"]))
        elif raw.startswith(">"):
            callout_text = inline_fmt(raw.lstrip("> ").strip())
            story.append(Paragraph(f"<b>NOTE:</b> {callout_text}", S["callout"]))
        else:
            story.append(Paragraph(inline_fmt(raw), S["body"]))

        i += 1

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Generated PDF: {pdf_filename}")

if __name__ == "__main__":
    # Generate CUSTOMER_SETUP_GUIDE_v3.12.pdf
    build_pdf("CUSTOMER_SETUP_GUIDE_v3.12.md", "CUSTOMER_SETUP_GUIDE_v3.12.pdf", "AICyberAuditBox v3.12 — Customer Setup & Operations Guide")
    
    # Generate DEPLOYMENT_GUIDE_v3.12.pdf
    build_pdf("DEPLOYMENT_GUIDE.md", "DEPLOYMENT_GUIDE_v3.12.pdf", "AICyberAuditBox v3.12 — Customer Deployment Guide")
    
    # Generate AICyberAuditBox_Rolling_Update_Playbook_v3.12.pdf
    build_pdf("ROLLING_UPDATE_PLAYBOOK.md", "AICyberAuditBox_Rolling_Update_Playbook_v3.12.pdf", "AICyberAuditBox — Rolling Update & Maintenance Playbook")
