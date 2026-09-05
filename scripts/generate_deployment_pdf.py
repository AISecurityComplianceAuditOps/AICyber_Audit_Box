"""Generate DEPLOYMENT_GUIDE.pdf from DEPLOYMENT_GUIDE.md using ReportLab."""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table, TableStyle, HRFlowable, Preformatted)
from reportlab.lib.enums import TA_LEFT, TA_CENTER
import re, os

OUTPUT = r"c:\Users\HP\Desktop\audit test_box\DEPLOYMENT_GUIDE.pdf"
MD     = r"c:\Users\HP\Desktop\audit test_box\DEPLOYMENT_GUIDE.md"

with open(MD, encoding="utf-8", errors="ignore") as f:
    lines = f.readlines()

doc = SimpleDocTemplate(
    OUTPUT, pagesize=A4,
    leftMargin=2*cm, rightMargin=2*cm,
    topMargin=2*cm, bottomMargin=2*cm
)

styles = getSampleStyleSheet()

# Custom styles
S = {
    "h1": ParagraphStyle("h1", parent=styles["Heading1"], fontSize=18,
                          textColor=colors.HexColor("#1a1a2e"), spaceAfter=10),
    "h2": ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13,
                          textColor=colors.HexColor("#16213e"), spaceAfter=6),
    "body": ParagraphStyle("body", parent=styles["Normal"], fontSize=9.5,
                            leading=14, spaceAfter=4),
    "bullet": ParagraphStyle("bullet", parent=styles["Normal"], fontSize=9.5,
                               leading=14, leftIndent=14, spaceAfter=3,
                               bulletIndent=4),
    "code": ParagraphStyle("code", parent=styles["Code"], fontSize=8,
                             fontName="Courier", backColor=colors.HexColor("#f0f0f0"),
                             leftIndent=10, rightIndent=10, spaceAfter=6,
                             leading=12),
    "note": ParagraphStyle("note", parent=styles["Normal"], fontSize=9,
                             textColor=colors.HexColor("#555555"), leading=13),
}

story = []

def escape(t):
    return (t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace("→", "&#8594;").replace("—", "&#8212;").replace("–", "&#8211;")
             .replace("✅", "OK").replace("🎉", ""))

def inline_fmt(t):
    t = escape(t)
    # Bold **text**
    t = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', t)
    # Inline code `text`
    t = re.sub(r'`([^`]+)`', r'<font name="Courier" size="8" color="#c7254e">\1</font>', t)
    return t

i = 0
in_code = False
code_buf = []
in_table = False
table_rows = []

while i < len(lines):
    line = lines[i].rstrip("\n")

    # Code blocks
    if line.strip().startswith("```"):
        if not in_code:
            in_code = True
            code_buf = []
        else:
            in_code = False
            story.append(Preformatted("\n".join(code_buf), S["code"]))
            story.append(Spacer(1, 4))
        i += 1
        continue

    if in_code:
        code_buf.append(line)
        i += 1
        continue

    # Table rows
    if line.strip().startswith("|"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if all(re.match(r"^[-:]+$", c) for c in cells if c):
            i += 1
            continue
        table_rows.append(cells)
        i += 1
        # Check if next line is also a table row
        if i < len(lines) and lines[i].strip().startswith("|"):
            continue
        # Render table
        if table_rows:
            col_count = max(len(r) for r in table_rows)
            # Normalize rows
            data = []
            for r in table_rows:
                while len(r) < col_count:
                    r.append("")
                data.append([Paragraph(inline_fmt(c), S["body"]) for c in r])

            col_w = (A4[0] - 4*cm) / col_count
            tbl = Table(data, colWidths=[col_w]*col_count, repeatRows=1)
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#16213e")),
                ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0), (-1,-1), 8.5),
                ("GRID",       (0,0), (-1,-1), 0.4, colors.HexColor("#cccccc")),
                ("ROWBACKGROUNDS", (0,1), (-1,-1),
                 [colors.white, colors.HexColor("#f7f7f7")]),
                ("VALIGN",     (0,0), (-1,-1), "TOP"),
                ("TOPPADDING", (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ]))
            story.append(tbl)
            story.append(Spacer(1, 8))
            table_rows = []
        continue

    # Headings
    if line.startswith("# "):
        story.append(HRFlowable(width="100%", thickness=1,
                                 color=colors.HexColor("#1a1a2e"), spaceAfter=4))
        story.append(Paragraph(inline_fmt(line[2:]), S["h1"]))
        story.append(Spacer(1, 4))
    elif line.startswith("## "):
        story.append(Spacer(1, 6))
        story.append(Paragraph(inline_fmt(line[3:]), S["h2"]))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                 color=colors.HexColor("#aaaaaa"), spaceAfter=4))
    # Numbered list
    elif re.match(r"^\d+\. ", line):
        txt = re.sub(r"^\d+\. ", "", line)
        story.append(Paragraph(f"&#8226; {inline_fmt(txt)}", S["bullet"]))
    # Bullet list
    elif line.strip().startswith("- "):
        txt = line.strip()[2:]
        story.append(Paragraph(f"&#8226; {inline_fmt(txt)}", S["bullet"]))
    # Indented continuation
    elif line.startswith("  ") and line.strip():
        story.append(Paragraph(inline_fmt(line.strip()), S["note"]))
    # Blank line
    elif not line.strip():
        story.append(Spacer(1, 4))
    # Normal paragraph
    else:
        story.append(Paragraph(inline_fmt(line), S["body"]))

    i += 1

# Footer function
def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawString(2*cm, 1.2*cm,
        "AICyberAuditBox v3.8 — Confidential — Air-Gapped Deployment Guide")
    canvas.drawRightString(A4[0]-2*cm, 1.2*cm, f"Page {doc.page}")
    canvas.restoreState()

doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(f"[OK] PDF saved to: {OUTPUT}")
