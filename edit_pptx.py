# -*- coding: utf-8 -*-
"""
Edit AICyberAuditBox PPTX:
1. Fix Asset Category visibility issue (OEM Readiness Matrix)
2. Add new slides: Bundling explanation, Binary Protection in Docker
3. Add a PQC Demo Workflow slide showing the screenshots
"""

try:
    from pptx import Presentation
    from pptx.util import Inches, Pt, Emu, Cm
    from pptx.dml.color import RGBColor
    from pptx.enum.text import PP_ALIGN
    from pptx.oxml.ns import qn
    from pptx.oxml import parse_xml
    import copy
    from lxml import etree
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-pptx", "lxml", "-q"])
    from pptx import Presentation
    from pptx.util import Inches, Pt, Emu, Cm
    from pptx.dml.color import RGBColor
    from pptx.enum.text import PP_ALIGN
    from pptx.oxml.ns import qn

IN  = r"samples/AICyberAuditOPS Sample Data/AICyberAuditBox_Presentation_Final_Complete PQC_DEMO 1111.pptx"
OUT = r"samples/AICyberAuditOPS Sample Data/AICyberAuditBox_Presentation_Updated.pptx"

# ── Colour palette ────────────────────────────────────────────────────────────
C_DARK    = RGBColor(0x1a, 0x1a, 0x2e)
C_BLUE    = RGBColor(0x0f, 0x34, 0x60)
C_RED     = RGBColor(0xe9, 0x45, 0x60)
C_GREEN   = RGBColor(0x1e, 0x84, 0x49)
C_ORANGE  = RGBColor(0xd3, 0x54, 0x00)
C_WHITE   = RGBColor(0xff, 0xff, 0xff)
C_LGREY   = RGBColor(0xf0, 0xf4, 0xf8)
C_GREY    = RGBColor(0x7f, 0x8c, 0x8d)
C_YELLOW  = RGBColor(0xff, 0xd7, 0x00)
C_ACCENT  = RGBColor(0x27, 0xae, 0xc0)

W = Inches(13.333)
H = Inches(7.5)


def rgb(r, g, b):
    return RGBColor(r, g, b)


def add_rect(slide, l, t, w, h, fill_rgb, alpha=None):
    shape = slide.shapes.add_shape(1, l, t, w, h)
    shape.line.fill.background()
    shape.line.width = 0
    fill = shape.fill
    fill.solid()
    fill.fore_color.rgb = fill_rgb
    return shape


def add_text(slide, text, l, t, w, h,
             font_size=18, bold=False, italic=False,
             color=C_DARK, align=PP_ALIGN.LEFT,
             wrap=True, font_name="Calibri"):
    txb = slide.shapes.add_textbox(l, t, w, h)
    tf  = txb.text_frame
    tf.word_wrap = wrap
    p   = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size = Pt(font_size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = color
    run.font.name = font_name
    return txb


def add_multiline_textbox(slide, lines, l, t, w, h,
                           font_size=11, color=C_DARK,
                           font_name="Calibri", line_bold=None):
    """lines = list of (text, bold, size, color) or just str"""
    txb = slide.shapes.add_textbox(l, t, w, h)
    tf  = txb.text_frame
    tf.word_wrap = True
    for idx, line in enumerate(lines):
        if isinstance(line, str):
            bold_flag = False
            sz = font_size
            col = color
            txt = line
        else:
            txt, bold_flag, sz, col = line
        p = tf.paragraphs[0] if idx == 0 else tf.add_paragraph()
        p.space_after = Pt(2)
        run = p.add_run()
        run.text = txt
        run.font.size = Pt(sz)
        run.font.bold = bold_flag
        run.font.color.rgb = col
        run.font.name = font_name
    return txb


def add_table(slide, headers, rows, l, t, w, h,
              header_fill=C_BLUE, row_fills=None,
              col_widths=None, font_size=10):
    """Add a simple table with styled header."""
    num_rows = 1 + len(rows)
    num_cols = len(headers)
    tbl = slide.shapes.add_table(num_rows, num_cols, l, t, w, h).table

    # Default col widths
    if col_widths:
        for i, cw in enumerate(col_widths):
            tbl.columns[i].width = cw
    else:
        cw = w // num_cols
        for i in range(num_cols):
            tbl.columns[i].width = cw

    def style_cell(cell, text, bg, fg, bold=False, sz=None):
        cell.text = text
        cell.fill.solid()
        cell.fill.fore_color.rgb = bg
        tf = cell.text_frame
        tf.paragraphs[0].alignment = PP_ALIGN.LEFT
        run = tf.paragraphs[0].runs[0] if tf.paragraphs[0].runs else tf.paragraphs[0].add_run()
        run.text = text
        run.font.bold = bold
        run.font.size = Pt(sz or font_size)
        run.font.color.rgb = fg
        run.font.name = "Calibri"

    for ci, h_text in enumerate(headers):
        style_cell(tbl.cell(0, ci), h_text, header_fill, C_WHITE, bold=True, sz=font_size)

    row_fills = row_fills or [C_LGREY, C_WHITE]
    for ri, row in enumerate(rows):
        bg = row_fills[ri % len(row_fills)]
        for ci, cell_text in enumerate(row):
            style_cell(tbl.cell(ri+1, ci), str(cell_text), bg, C_DARK, sz=font_size)

    return tbl


def add_badge(slide, text, l, t, w, h, fill, text_color=C_WHITE, size=9):
    shape = slide.shapes.add_shape(9, l, t, w, h)  # rounded rect
    shape.line.fill.background()
    shape.line.width = 0
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    tf = shape.text_frame
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    run = tf.paragraphs[0].add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = True
    run.font.color.rgb = text_color
    run.font.name = "Calibri"
    return shape


prs = Presentation(IN)


# ════════════════════════════════════════════════════════════════════════════
# FIX SLIDE 1 — Add subtitle / fix Asset Category mention
# ════════════════════════════════════════════════════════════════════════════
slide1 = prs.slides[0]

# Add a note about what "Asset Category" means and fix visibility
add_text(slide1,
    "AI-Powered Post-Quantum Cryptography Audit Platform",
    Inches(0.4), Inches(3.2), Inches(8), Inches(0.6),
    font_size=20, bold=True, color=C_WHITE)

add_text(slide1,
    "Automated VAPT + ISO 27001 + PQC Readiness Scanning with AI-driven findings, "
    "OEM Asset Category tagging, and quantum-vulnerable algorithm detection.",
    Inches(0.4), Inches(3.9), Inches(9), Inches(1.0),
    font_size=13, color=RGBColor(0xae, 0xd6, 0xf1), wrap=True)


# ════════════════════════════════════════════════════════════════════════════
# NEW SLIDE A — PQC Demo Workflow (screenshots explanation)
# ════════════════════════════════════════════════════════════════════════════
slide_layout = prs.slide_layouts[6]  # blank

slideA = prs.slides.add_slide(slide_layout)

# Background
add_rect(slideA, 0, 0, W, H, C_DARK)
add_rect(slideA, 0, 0, W, Inches(1.0), C_BLUE)

# Title
add_text(slideA, "PQC Demo: Step-by-Step Audit Workflow",
         Inches(0.4), Inches(0.12), Inches(10), Inches(0.7),
         font_size=24, bold=True, color=C_WHITE)
add_text(slideA, "From file upload to quantum-vulnerability findings with OEM Asset Category",
         Inches(0.4), Inches(0.72), Inches(10), Inches(0.35),
         font_size=11, color=RGBColor(0xae, 0xd6, 0xf1))

# Step boxes — row 1
steps = [
    ("01", "Upload Evidence Files", "Drag & drop config files\n(nginx, ssh, db configs,\ncerts, XLSX, PDF, DOCX)"),
    ("02", "Select Target Framework", "Choose: PQC Readiness\nAI Auto-Scoping detects\n12/12 controls automatically"),
    ("03", "Run Audit Scan", "AI engine parses all files\nExtracts: algorithms, certs,\ncipher suites, key sizes"),
]

for idx, (num, title, desc) in enumerate(steps):
    x = Inches(0.3 + idx * 4.3)
    # Box
    add_rect(slideA, x, Inches(1.2), Inches(4.0), Inches(2.3), C_BLUE)
    # Number badge
    add_badge(slideA, num, x + Inches(0.15), Inches(1.3), Inches(0.55), Inches(0.45), C_RED, size=13)
    # Title
    add_text(slideA, title, x + Inches(0.8), Inches(1.32), Inches(3.1), Inches(0.45),
             font_size=12, bold=True, color=C_WHITE)
    # Desc
    add_text(slideA, desc, x + Inches(0.15), Inches(1.82), Inches(3.7), Inches(0.9),
             font_size=10, color=RGBColor(0xae, 0xd6, 0xf1), wrap=True)

# Arrow between steps
for idx in range(2):
    x = Inches(4.15 + idx * 4.3)
    add_text(slideA, "-->", x, Inches(2.1), Inches(0.4), Inches(0.4),
             font_size=18, bold=True, color=C_YELLOW, align=PP_ALIGN.CENTER)

# Step boxes — row 2 (results)
steps2 = [
    ("04", "Audit Records & Gaps", "Compliance summary:\n- Compliant / Non-Compliant\n- P1 Critical / P2 High findings\nCryptographically locked to ShakthiDB"),
    ("05", "OEM Readiness Matrix", "Asset Category tagging:\n- NGINX -> Load Balancer\n- MySQL / PostgreSQL -> Database\nUpgrade status per product"),
    ("06", "QBOM + PQC Report", "Quantum Bill of Materials:\n- All vulnerable algorithms\n- Risk Score (0-100)\n- Remediation steps per finding"),
]

for idx, (num, title, desc) in enumerate(steps2):
    x = Inches(0.3 + idx * 4.3)
    add_rect(slideA, x, Inches(3.85), Inches(4.0), Inches(2.4), RGBColor(0x0a, 0x25, 0x45))
    add_badge(slideA, num, x + Inches(0.15), Inches(3.95), Inches(0.55), Inches(0.45), C_GREEN, size=13)
    add_text(slideA, title, x + Inches(0.8), Inches(3.97), Inches(3.1), Inches(0.45),
             font_size=12, bold=True, color=C_WHITE)
    add_text(slideA, desc, x + Inches(0.15), Inches(4.47), Inches(3.7), Inches(1.5),
             font_size=10, color=RGBColor(0xae, 0xd6, 0xf1), wrap=True)

# Down arrows
for idx in range(3):
    x = Inches(2.0 + idx * 4.3)
    add_text(slideA, "v", x, Inches(3.45), Inches(0.4), Inches(0.4),
             font_size=16, bold=True, color=C_YELLOW, align=PP_ALIGN.CENTER)

# Footer
add_text(slideA, "Proprietary and Confidential | DhiWare Technologies Pvt Ltd",
         Inches(0.3), Inches(7.15), Inches(12), Inches(0.3),
         font_size=8, color=C_GREY, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# NEW SLIDE B — Asset Category Fix & OEM Readiness Matrix Explanation
# ════════════════════════════════════════════════════════════════════════════
slideB = prs.slides.add_slide(slide_layout)
add_rect(slideB, 0, 0, W, H, C_DARK)
add_rect(slideB, 0, 0, W, Inches(1.0), C_BLUE)

add_text(slideB, "OEM Readiness Matrix: Asset Category",
         Inches(0.4), Inches(0.12), Inches(11), Inches(0.7),
         font_size=24, bold=True, color=C_WHITE)
add_text(slideB, "How the system classifies each product into its Asset Category automatically",
         Inches(0.4), Inches(0.72), Inches(10), Inches(0.35),
         font_size=11, color=RGBColor(0xae, 0xd6, 0xf1))

# What is Asset Category box
add_rect(slideB, Inches(0.3), Inches(1.15), Inches(5.8), Inches(2.5), C_BLUE)
add_text(slideB, "What is Asset Category?",
         Inches(0.45), Inches(1.22), Inches(5.5), Inches(0.45),
         font_size=14, bold=True, color=C_YELLOW)
add_text(slideB,
    "Asset Category is the infrastructure role assigned to each "
    "OEM product found in your scanned configuration files.\n\n"
    "The AI engine reads product names (NGINX, MySQL, PostgreSQL, etc.) "
    "from config files and automatically tags them with their function "
    "in your network -- so auditors instantly see WHAT TYPE of asset "
    "is quantum-vulnerable, not just which file.",
    Inches(0.45), Inches(1.72), Inches(5.5), Inches(1.7),
    font_size=10, color=C_WHITE, wrap=True)

# Why it was not visible
add_rect(slideB, Inches(6.3), Inches(1.15), Inches(6.6), Inches(2.5), RGBColor(0x4a, 0x0a, 0x15))
add_text(slideB, "Why Was Asset Category Not Visible?",
         Inches(6.45), Inches(1.22), Inches(6.2), Inches(0.45),
         font_size=14, bold=True, color=C_RED)
add_text(slideB,
    "The OEM Readiness Matrix table in the UI has 3 columns:\n"
    "  Product | Status | Asset Category\n\n"
    "Asset Category values were present in the database but the "
    "column was cut off / not rendered in earlier report exports "
    "due to table width constraints.\n\n"
    "Fix: Column width corrected + Asset Category now always "
    "included in both the UI table and PDF/PPTX exports.",
    Inches(6.45), Inches(1.72), Inches(6.2), Inches(1.7),
    font_size=10, color=C_WHITE, wrap=True)

# OEM Table
add_text(slideB, "OEM Readiness Matrix — Full View (with Asset Category)",
         Inches(0.3), Inches(3.85), Inches(12), Inches(0.4),
         font_size=13, bold=True, color=C_WHITE)

add_table(slideB,
    ["Product / OEM", "Quantum Status", "Upgrade Status", "Asset Category", "Finding Source"],
    [
        ["NGINX",      "VULNERABLE",  "Upgrade Required", "Load Balancer", "nginx_intermediate.conf.txt"],
        ["MySQL",      "VULNERABLE",  "Upgrade Required", "Database",      "db.config"],
        ["PostgreSQL", "VULNERABLE",  "Upgrade Required", "Database",      "aqt.config"],
        ["OpenSSH",    "VULNERABLE",  "Patch Available",  "Remote Access", "ssh_config"],
        ["OpenSSL",    "VULNERABLE",  "Upgrade Required", "Crypto Library","nginx_intermediate.conf.txt"],
    ],
    Inches(0.3), Inches(4.3), Inches(12.7), Inches(2.6),
    header_fill=C_BLUE,
    col_widths=[Inches(2.0), Inches(2.2), Inches(2.2), Inches(2.2), Inches(4.1)],
    font_size=10
)

add_text(slideB, "Proprietary and Confidential | DhiWare Technologies Pvt Ltd",
         Inches(0.3), Inches(7.15), Inches(12), Inches(0.3),
         font_size=8, color=C_GREY, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# NEW SLIDE C — PQC Finding Deep-Dive (from screenshot 1)
# ════════════════════════════════════════════════════════════════════════════
slideC = prs.slides.add_slide(slide_layout)
add_rect(slideC, 0, 0, W, H, C_DARK)
add_rect(slideC, 0, 0, W, Inches(1.0), C_BLUE)

add_text(slideC, "PQC Finding: What Each Field Means",
         Inches(0.4), Inches(0.12), Inches(11), Inches(0.7),
         font_size=24, bold=True, color=C_WHITE)
add_text(slideC, "Anatomy of a single quantum-vulnerability finding — NGINX ECDSA example",
         Inches(0.4), Inches(0.72), Inches(10), Inches(0.35),
         font_size=11, color=RGBColor(0xae, 0xd6, 0xf1))

# Left column — field explanations
fields = [
    ("TARGET HOST & SCOPE",   "Which file or host was scanned\nEx: nginx_intermediate.conf.txt"),
    ("OWASP TOP 10 CATEGORY", "Maps finding to OWASP risk category\nEx: A02:2021 Cryptographic Failures"),
    ("RISK CATEGORY",         "Operational risk label\nEx: Security Misconfiguration"),
    ("CIA IMPACT",            "Confidentiality / Integrity / Availability\nC:HIGH | I:HIGH | A:NONE"),
    ("QUANTUM READINESS",     "VULNERABLE / SAFE / WEAK\nAsset name + algorithm detected"),
    ("ATTACK VECTOR",         "External/Internal + threat model\nEx: Nation-state harvest-now-decrypt-later"),
    ("RISK SCORE",            "0-100 criticality score\nEx: 84/100 = CRITICAL"),
    ("CVE REFERENCES",        "Linked CVEs on NVD database\nOr Vendor End-of-Life advisory"),
]

for idx, (label, desc) in enumerate(fields):
    row = idx % 4
    col = idx // 4
    x = Inches(0.3 + col * 6.5)
    y = Inches(1.15 + row * 1.48)
    add_rect(slideC, x, y, Inches(6.1), Inches(1.35), C_BLUE)
    add_badge(slideC, label, x + Inches(0.1), y + Inches(0.1), Inches(5.8), Inches(0.3),
              RGBColor(0x0a, 0x25, 0x45), text_color=C_ACCENT, size=8)
    add_text(slideC, desc, x + Inches(0.15), y + Inches(0.45), Inches(5.7), Inches(0.8),
             font_size=10, color=C_WHITE, wrap=True)

add_text(slideC, "Proprietary and Confidential | DhiWare Technologies Pvt Ltd",
         Inches(0.3), Inches(7.15), Inches(12), Inches(0.3),
         font_size=8, color=C_GREY, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# NEW SLIDE D — Bundling Architecture
# ════════════════════════════════════════════════════════════════════════════
slideD = prs.slides.add_slide(slide_layout)
add_rect(slideD, 0, 0, W, H, C_DARK)
add_rect(slideD, 0, 0, W, Inches(1.0), C_BLUE)

add_text(slideD, "Deployment Bundling Architecture",
         Inches(0.4), Inches(0.12), Inches(11), Inches(0.7),
         font_size=24, bold=True, color=C_WHITE)
add_text(slideD, "Air-gapped customer delivery via Docker image bundles — no internet required at customer site",
         Inches(0.4), Inches(0.72), Inches(11), Inches(0.35),
         font_size=11, color=RGBColor(0xae, 0xd6, 0xf1))

# 3 bundle types
bundles = [
    ("FULL BUNDLE",   "~7-8 GB", "First install /\nDisaster recovery",
     C_RED,   "docker save 5 images -> .tar\nAll services included:\n  app + llm + llm-embed\n  shakthidb + redis",
     "python build_customer_bundle.py\n  --version 3.23 --full"),
    ("DELTA BUNDLE",  "~2 GB",   "App code updated\n(LLM/DB unchanged)",
     C_ORANGE, "Rebuilds only changed service\nOther containers keep running\nCustomer runs docker load\nthen restarts only that service",
     ".\\update_bundle.ps1\n  -Version 3.24 -DeltaOnly"),
    ("PATCH BUNDLE",  "~6 MB",   "Python source-only fix\n(no new packages)",
     C_GREEN,  "Ships only src/ folder\nCustomer rebuilds on top of\nexisting image using cached\nlayers -> seconds to apply",
     "python build_customer_bundle.py\n  --version 3.24 --patch 3.23"),
]

for idx, (name, size, when, color, internal, cmd) in enumerate(bundles):
    x = Inches(0.3 + idx * 4.35)
    # Header
    add_rect(slideD, x, Inches(1.1), Inches(4.1), Inches(0.6), color)
    add_text(slideD, name, x + Inches(0.1), Inches(1.15), Inches(2.5), Inches(0.5),
             font_size=13, bold=True, color=C_WHITE)
    add_text(slideD, size, x + Inches(2.6), Inches(1.15), Inches(1.4), Inches(0.5),
             font_size=13, bold=True, color=C_WHITE, align=PP_ALIGN.RIGHT)

    # When box
    add_rect(slideD, x, Inches(1.7), Inches(4.1), Inches(0.85), RGBColor(0x0a, 0x25, 0x45))
    add_text(slideD, "WHEN TO USE:", x + Inches(0.1), Inches(1.72), Inches(3.8), Inches(0.25),
             font_size=8, bold=True, color=C_ACCENT)
    add_text(slideD, when, x + Inches(0.1), Inches(1.95), Inches(3.8), Inches(0.55),
             font_size=10, color=C_WHITE, wrap=True)

    # How it works box
    add_rect(slideD, x, Inches(2.6), Inches(4.1), Inches(2.2), C_BLUE)
    add_text(slideD, "HOW IT WORKS INTERNALLY:", x+Inches(0.1), Inches(2.65), Inches(3.8), Inches(0.3),
             font_size=8, bold=True, color=C_YELLOW)
    add_text(slideD, internal, x + Inches(0.1), Inches(2.95), Inches(3.8), Inches(1.7),
             font_size=10, color=C_WHITE, wrap=True)

    # Command box
    add_rect(slideD, x, Inches(4.85), Inches(4.1), Inches(1.1), RGBColor(0x0d, 0x0d, 0x1a))
    add_text(slideD, "COMMAND:", x + Inches(0.1), Inches(4.9), Inches(3.8), Inches(0.25),
             font_size=8, bold=True, color=C_GREY)
    add_text(slideD, cmd, x + Inches(0.1), Inches(5.15), Inches(3.8), Inches(0.75),
             font_size=9, color=C_GREEN, font_name="Courier New", wrap=True)

# Customer side
add_rect(slideD, Inches(0.3), Inches(6.1), Inches(12.7), Inches(1.0), RGBColor(0x0a, 0x25, 0x45))
add_text(slideD, "CUSTOMER SIDE (Same for all bundle types):",
         Inches(0.45), Inches(6.15), Inches(5), Inches(0.3),
         font_size=9, bold=True, color=C_ACCENT)
add_text(slideD,
    "1. docker load -i bundle.tar      2. docker compose -f docker-compose.customer.yml up -d      3. Open http://localhost:8000",
    Inches(0.45), Inches(6.48), Inches(12.2), Inches(0.5),
    font_size=10, color=C_WHITE, font_name="Courier New")

add_text(slideD, "Proprietary and Confidential | DhiWare Technologies Pvt Ltd",
         Inches(0.3), Inches(7.15), Inches(12), Inches(0.3),
         font_size=8, color=C_GREY, align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════════════════
# NEW SLIDE E — Binary Protection in Docker
# ════════════════════════════════════════════════════════════════════════════
slideE = prs.slides.add_slide(slide_layout)
add_rect(slideE, 0, 0, W, H, C_DARK)
add_rect(slideE, 0, 0, W, Inches(1.0), C_BLUE)

add_text(slideE, "Source Code Protection: Binary in Docker",
         Inches(0.4), Inches(0.12), Inches(11), Inches(0.7),
         font_size=24, bold=True, color=C_WHITE)
add_text(slideE, "Preventing reverse engineering of Python source inside Docker images",
         Inches(0.4), Inches(0.72), Inches(10), Inches(0.35),
         font_size=11, color=RGBColor(0xae, 0xd6, 0xf1))

# Problem box
add_rect(slideE, Inches(0.3), Inches(1.1), Inches(12.7), Inches(0.9), RGBColor(0x4a, 0x0a, 0x15))
add_text(slideE, "THE PROBLEM:", Inches(0.45), Inches(1.15), Inches(2), Inches(0.35),
         font_size=10, bold=True, color=C_RED)
add_text(slideE,
    "By default, anyone with the Docker image can run:   docker run --rm -it aicyberauditbox-app bash   "
    "and read all Python source files (audit_chains.py, bg_worker.py, etc.) -- full IP exposure.",
    Inches(2.3), Inches(1.15), Inches(10.5), Inches(0.75),
    font_size=10, color=C_WHITE, font_name="Courier New", wrap=True)

# 3 solution columns
solutions = [
    ("NUITKA", "Compile Python -> C++ Binary", "Very High",
     C_GREEN,
     "How it works:\nPython source compiled to\nnative machine code (.so files)\nNo decompiler can recover it",
     "# Dockerfile.app (multi-stage)\nFROM python:3.11 AS builder\nRUN pip install nuitka\nCOPY src/ /app/src/\nRUN python -m nuitka --module \\\n    src/api/main.py \\\n    --include-package=src\n\nFROM python:3.11-slim\n# Only .so binaries copied\n# NO .py files in final image\nCOPY --from=builder /app/dist /app/"),
    ("PYARMOR", "Encrypt Python Bytecode",     "High",
     C_ORANGE,
     "How it works:\nBytecode (.pyc) encrypted\nwith a runtime key\nRuns normally but cannot\nbe read or decompiled",
     "pip install pyarmor\n\n# Encrypt source\npyarmor gen --recursive src/\n\n# Dockerfile: copy obfuscated\n# NOT the original src/\nCOPY obfuscated/ /app/src/"),
    ("CYTHON",  "Compile Python -> C Extension", "High",
     C_ACCENT,
     "How it works:\nPython .py -> C .so extension\nBuilt into Docker as binary\nSource code never ships",
     "# Compile .py to C extension\ncython --embed audit_chains.py\ngcc -o audit_chains.so \\\n    audit_chains.c\n\n# Only ship .so in Docker\n# No .py files included"),
]

for idx, (name, subtitle, level, color, how, cmd) in enumerate(solutions):
    x = Inches(0.3 + idx * 4.35)
    add_rect(slideE, x, Inches(2.1), Inches(4.1), Inches(0.6), color)
    add_text(slideE, name, x+Inches(0.1), Inches(2.15), Inches(2.8), Inches(0.5),
             font_size=14, bold=True, color=C_WHITE)
    add_text(slideE, f"Protection: {level}", x+Inches(2.9), Inches(2.22), Inches(1.1), Inches(0.35),
             font_size=8, bold=True, color=C_WHITE, align=PP_ALIGN.RIGHT)

    add_rect(slideE, x, Inches(2.7), Inches(4.1), Inches(0.15), RGBColor(0x0a, 0x25, 0x45))
    add_text(slideE, subtitle, x+Inches(0.1), Inches(2.72), Inches(3.9), Inches(0.5),
             font_size=9, color=C_ACCENT, italic=True)

    add_rect(slideE, x, Inches(2.9), Inches(4.1), Inches(1.2), C_BLUE)
    add_text(slideE, how, x+Inches(0.1), Inches(2.95), Inches(3.8), Inches(1.0),
             font_size=9, color=C_WHITE, wrap=True)

    add_rect(slideE, x, Inches(4.15), Inches(4.1), Inches(2.5), RGBColor(0x0d, 0x0d, 0x1a))
    add_text(slideE, "DOCKERFILE / COMMAND:", x+Inches(0.1), Inches(4.2), Inches(3.8), Inches(0.3),
             font_size=8, bold=True, color=C_GREY)
    add_text(slideE, cmd, x+Inches(0.1), Inches(4.5), Inches(3.8), Inches(2.0),
             font_size=8, color=C_GREEN, font_name="Courier New", wrap=True)

# Recommendation
add_rect(slideE, Inches(0.3), Inches(6.72), Inches(12.7), Inches(0.6), C_BLUE)
add_text(slideE, "RECOMMENDATION:",
         Inches(0.45), Inches(6.77), Inches(2), Inches(0.4),
         font_size=9, bold=True, color=C_YELLOW)
add_text(slideE,
    "Use NUITKA with multi-stage Docker build -- Stage 1 compiles all .py to .so, "
    "Stage 2 copies only binaries. Source code never exists in the shipped image.",
    Inches(2.5), Inches(6.77), Inches(10.3), Inches(0.5),
    font_size=10, color=C_WHITE, wrap=True)

add_text(slideE, "Proprietary and Confidential | DhiWare Technologies Pvt Ltd",
         Inches(0.3), Inches(7.15), Inches(12), Inches(0.3),
         font_size=8, color=C_GREY, align=PP_ALIGN.CENTER)


# ── Save ─────────────────────────────────────────────────────────────────────
prs.save(OUT)
print(f"[OK] PPTX saved: {OUT}")
print(f"     Total slides: {len(prs.slides)}")
