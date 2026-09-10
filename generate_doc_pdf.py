# -*- coding: utf-8 -*-
"""
Generates AICyberAuditBox_Bundling_and_Binary_Protection.pdf
Run: python generate_doc_pdf.py
"""

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "reportlab", "-q"])
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER

OUT = "AICyberAuditBox_Bundling_and_Binary_Protection_Guide.pdf"

# ── Colours ──────────────────────────────────────────────────────────────────
DARK_BG   = colors.HexColor("#1a1a2e")
ACCENT    = colors.HexColor("#0f3460")
HIGHLIGHT = colors.HexColor("#e94560")
LIGHT_BG  = colors.HexColor("#f0f4f8")
CODE_BG   = colors.HexColor("#1e1e2e")
CODE_FG   = colors.HexColor("#cdd6f4")
GREEN     = colors.HexColor("#1e8449")
ORANGE    = colors.HexColor("#d35400")
GREY      = colors.HexColor("#7f8c8d")

doc = SimpleDocTemplate(
    OUT, pagesize=A4,
    leftMargin=2*cm, rightMargin=2*cm,
    topMargin=2*cm, bottomMargin=2*cm
)

styles = getSampleStyleSheet()

def S(name, **kw):
    base = styles["Normal"]
    return ParagraphStyle(name, parent=base, **kw)

H1  = S("H1",  fontSize=22, textColor=DARK_BG, spaceAfter=6,  spaceBefore=14, fontName="Helvetica-Bold", leading=28)
H2  = S("H2",  fontSize=15, textColor=ACCENT,  spaceAfter=4,  spaceBefore=12, fontName="Helvetica-Bold", leading=20)
H3  = S("H3",  fontSize=12, textColor=HIGHLIGHT, spaceAfter=3, spaceBefore=8, fontName="Helvetica-Bold", leading=16)
BODY = S("BODY", fontSize=10, textColor=colors.HexColor("#2c3e50"), spaceAfter=4, leading=15)
CODE = S("CODE", fontSize=9,  textColor=CODE_FG, backColor=CODE_BG,
          fontName="Courier", spaceAfter=6, spaceBefore=4,
          leftIndent=10, rightIndent=10, leading=13,
          borderPadding=(6,8,6,8))
NOTE = S("NOTE", fontSize=9, textColor=colors.HexColor("#555"), leading=13,
          leftIndent=12, spaceAfter=4, italic=True)
BULLET = S("BULLET", fontSize=10, textColor=colors.HexColor("#2c3e50"),
            spaceAfter=3, leftIndent=16, leading=14, bulletIndent=6)

def h1(text):     return Paragraph(text, H1)
def h2(text):     return Paragraph(text, H2)
def h3(text):     return Paragraph(text, H3)
def p(text):      return Paragraph(text, BODY)
def code(text):   return Paragraph(text.replace("\n", "<br/>").replace(" ", "&nbsp;"), CODE)
def note(text):   return Paragraph(f"<i>{text}</i>", NOTE)
def bullet(text): return Paragraph(f"• &nbsp;{text}", BULLET)
def sp(h=6):      return Spacer(1, h)
def hr():         return HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dee2e6"), spaceAfter=6, spaceBefore=6)

def section_header(title, subtitle=""):
    data = [[Paragraph(title, ParagraphStyle("sh", fontSize=14, textColor=colors.white,
                fontName="Helvetica-Bold", leading=18)),
             Paragraph(subtitle, ParagraphStyle("ss", fontSize=9, textColor=colors.HexColor("#aed6f1"),
                fontName="Helvetica", leading=12))]]
    t = Table(data, colWidths=["100%"])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), ACCENT),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING",   (0,0), (-1,-1), 14),
        ("RIGHTPADDING",  (0,0), (-1,-1), 14),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [ACCENT]),
    ]))
    return t

def comparison_table(headers, rows, col_widths=None):
    data = [headers] + rows
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0),  ACCENT),
        ("TEXTCOLOR",    (0,0), (-1,0),  colors.white),
        ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [LIGHT_BG, colors.white]),
        ("GRID",         (0,0), (-1,-1), 0.4, colors.HexColor("#bdc3c7")),
        ("TOPPADDING",   (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0), (-1,-1), 6),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ("ALIGN",        (0,0), (-1,-1), "LEFT"),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    return t

# ── Build story ───────────────────────────────────────────────────────────────
story = []

# ── Cover block ──────────────────────────────────────────────────────────────
cover = Table([[
    Paragraph("AICyberAuditBox", ParagraphStyle("ct", fontSize=26, textColor=colors.white,
               fontName="Helvetica-Bold", leading=32)),
    ""],[
    Paragraph("Bundling &amp; Binary Protection Guide",
              ParagraphStyle("cs", fontSize=14, textColor=colors.HexColor("#aed6f1"),
                             fontName="Helvetica", leading=18)), ""]],
    colWidths=["80%","20%"])
cover.setStyle(TableStyle([
    ("BACKGROUND",    (0,0),(-1,-1), DARK_BG),
    ("TOPPADDING",    (0,0),(-1,-1), 20),
    ("BOTTOMPADDING", (0,0),(-1,-1), 20),
    ("LEFTPADDING",   (0,0),(-1,-1), 18),
]))
story += [cover, sp(14)]

# ════════════════════════════════════════════════════════════════════════════
# PART 1 — BUNDLING
# ════════════════════════════════════════════════════════════════════════════
story += [section_header("PART 1 — BUNDLING", "How we package and ship AICyberAuditBox to customers"), sp(10)]

story += [h2("What is Bundling?"), hr()]
story += [p("Bundling packages the entire application into Docker images and ships them as a single portable file. "
            "The customer can install and run the system on any machine <b>without an internet connection</b> (air-gapped)."), sp(4)]

story += [h2("We Have 3 Types of Bundles"), hr()]

# ── Full Bundle ──
story += [h3("1. Full Bundle — First-time / Fresh Install")]
story += [
    p("Builds <b>all 4 Docker services</b> and packages them into one large <b>.tar file (~7–8 GB)</b>."),
    bullet("aicyberauditbox-<b>app</b> → your FastAPI application"),
    bullet("aicyberauditbox-<b>llm</b> → LLM inference server"),
    bullet("aicyberauditbox-<b>llm-embed</b> → embedding server"),
    bullet("aicyberauditbox-<b>shakthidb</b> → PostgreSQL database"),
    bullet("redis:7-alpine → cache layer"),
    sp(4),
    p("<b>Command (developer side):</b>"),
    code("python build_customer_bundle.py --version 3.23 --full"),
    p("<b>Output — 2 files to ship to customer:</b>"),
    code("aicyberauditbox_bundle_v3.23.tar          (~7 GB - all images)\n"
         "aicyberauditbox_bundle_v3.23_companion.zip (~50 KB - compose + quickstart)"),
    p("<b>Customer installs with:</b>"),
    code("docker load -i aicyberauditbox_bundle_v3.23.tar\n"
         "docker compose -f docker-compose.customer.yml up -d\n"
         "# Open browser → http://localhost:8000"),
    sp(6),
]

# ── Delta Bundle ──
story += [h3("2. Delta/Update Bundle — App Code Updated")]
story += [
    p("When only the <b>app code changes</b> (not LLM or database), we rebuild only the changed image. "
      "The customer's LLM, database, and Redis <b>keep running</b> — only the app container restarts."),
    sp(4),
    p("<b>Command (developer side):</b>"),
    code("# App only update\n"
         ".\\update_bundle.ps1 -Version 3.24 -DeltaOnly\n\n"
         "# App + LLM update\n"
         ".\\update_bundle.ps1 -Version 3.24 -Services app,llm -DeltaOnly"),
    p("<b>Output — 2 files to ship to customer:</b>"),
    code("aicyberauditbox_delta_app_v3.24.tar          (~2 GB)\n"
         "aicyberauditbox_delta_app_v3.24_companion.zip (~50 KB)"),
    p("<b>Customer applies update with:</b>"),
    code("docker load -i aicyberauditbox_delta_app_v3.24.tar\n"
         "docker compose -f docker-compose.customer.yml up -d app"),
    sp(6),
]

# ── Patch Bundle ──
story += [h3("3. Patch Bundle — Code-Only Fix (Seconds to Apply)")]
story += [
    p("When only Python <b>source files change</b> (no new packages, no model change). "
      "Ships just the <b>src/ folder (~6 MB)</b>. Customer rebuilds on top of their existing image — "
      "all cached layers reused, takes seconds."),
    sp(4),
    p("<b>Command (developer side):</b>"),
    code("python build_customer_bundle.py --version 3.24 --patch 3.23"),
    sp(6),
]

# Comparison table
story += [h2("Bundle Comparison"), hr()]
story += [
    comparison_table(
        ["Bundle Type", "When to Use", "Size", "Command"],
        [
            ["Full Bundle",  "First install / disaster recovery", "~7–8 GB", "build_customer_bundle.py --full"],
            ["Delta Bundle", "App or service code updated",       "~2 GB",   "update_bundle.ps1 -DeltaOnly"],
            ["Patch Bundle", "Python source-only fix",            "~6 MB",   "build_customer_bundle.py --patch"],
        ],
        col_widths=[3.5*cm, 5.5*cm, 2*cm, 6.5*cm]
    ),
    sp(8),
]

# Internal flow
story += [h2("Internal Flow — How the Commands Work"), hr()]
story += [
    p("When you run <b>update_bundle.ps1</b>, it does these steps internally:"),
    sp(4),
    code("Step 1:  docker build\n"
         "         Reads Dockerfile.app → builds the image\n"
         "         Tags it: aicyberauditbox-app:3.24\n\n"
         "Step 2:  Bumps version in compose files\n"
         "         Finds  aicyberauditbox-app:3.23  in docker-compose files\n"
         "         Replaces with  aicyberauditbox-app:3.24  (auto, no manual edit)\n\n"
         "Step 3:  docker save\n"
         "         Exports Docker image → .tar file\n"
         "         (like zipping a Docker image into one portable file)\n\n"
         "Step 4:  Creates companion .zip\n"
         "         Zips docker-compose.customer.yml + QUICKSTART guide\n\n"
         "Output:  2 files ready to ship to customer"),
    sp(6),
]

story += [
    p("When the <b>customer runs docker load</b>:"),
    sp(4),
    code("docker load -i bundle.tar\n"
         "# Reverse of docker save — imports all images into their Docker\n\n"
         "docker compose -f docker-compose.customer.yml up -d\n"
         "# Starts all containers using the imported images\n"
         "# No internet needed — completely offline / air-gapped"),
    sp(10),
]

# ════════════════════════════════════════════════════════════════════════════
# PART 2 — BINARY PROTECTION
# ════════════════════════════════════════════════════════════════════════════
story += [section_header("PART 2 — BINARY PROTECTION IN DOCKER",
                          "Preventing reverse engineering of Python source code"), sp(10)]

story += [h2("The Problem — Python in Docker is Easy to Read"), hr()]
story += [
    p("By default, anyone who gets your Docker image can extract and read your full Python source code:"),
    code("docker run --rm -it aicyberauditbox-app bash\n"
         "cat /app/src/ai/audit_chains.py      # Full source code visible!\n"
         "cat /app/src/core/bg_worker.py        # All business logic exposed!"),
    p("This is a serious IP (intellectual property) risk when shipping to external customers."),
    sp(8),
]

story += [h2("3 Solutions to Protect Source Code"), hr()]

# Nuitka
story += [h3("Option 1: Nuitka — Compile Python to Native Binary (Best Protection)")]
story += [
    p("Nuitka converts Python source into <b>C++ compiled machine code</b>. "
      "No decompiler can recover readable Python from it. "
      "The final Docker image contains only binary <b>.so files</b> — no .py files at all."),
    sp(4),
    p("<b>How to use in Dockerfile.app:</b>"),
    code("# Stage 1 — Build (has source code, never shipped)\n"
         "FROM python:3.11 AS builder\n"
         "RUN pip install nuitka\n"
         "COPY src/ /app/src/\n"
         "RUN python -m nuitka --module src/api/main.py \\\\\n"
         "    --include-package=src \\\\\n"
         "    --output-dir=/app/dist\n\n"
         "# Stage 2 — Final image (only compiled binaries, NO .py files)\n"
         "FROM python:3.11-slim\n"
         "COPY --from=builder /app/dist /app/\n"
         "# Source code NEVER makes it into this final image"),
    note("Protection level: Very High — even if someone extracts the Docker image, they get machine code only."),
    sp(6),
]

# PyArmor
story += [h3("Option 2: PyArmor — Encrypt Python Bytecode (Easy to Add)")]
story += [
    p("PyArmor wraps <b>.pyc bytecode files with an encryption key</b>. "
      "The encrypted code runs normally inside Docker but cannot be read or decompiled outside."),
    sp(4),
    p("<b>Commands:</b>"),
    code("pip install pyarmor\n\n"
         "# Obfuscate/encrypt your source\n"
         "pyarmor gen --recursive src/\n\n"
         "# In Dockerfile.app — copy obfuscated folder, NOT src/\n"
         "COPY obfuscated/ /app/src/      # encrypted, not human-readable"),
    note("Protection level: High — bytecode is encrypted. Much harder to read than plain .pyc files."),
    sp(6),
]

# Cython
story += [h3("Option 3: Cython — Compile to C Extensions (.so files)")]
story += [
    p("Cython compiles Python files into <b>native C extension modules (.so files)</b>. "
      "These behave exactly like Python imports but contain no readable source."),
    code("# Compile .py to C extension\n"
         "cython --embed src/ai/audit_chains.py\n"
         "gcc -o audit_chains.so audit_chains.c\n\n"
         "# Ship only the .so file in Docker — no .py"),
    note("Protection level: High — .so files require expertise and tooling to partially analyze."),
    sp(8),
]

# Comparison table
story += [h2("Protection Level Comparison"), hr()]
story += [
    comparison_table(
        ["Method", "Protection Level", "Effort to Add", "Works in Docker"],
        [
            ["Nuitka",    "Very High — native C++ binary, no decompiler works",  "Medium", "Yes"],
            ["PyArmor",   "High — bytecode encrypted with runtime key",           "Easy",   "Yes"],
            ["Cython",    "High — native C extensions, no .py exposed",           "Medium", "Yes"],
            ["Plain Python", "None — anyone can read source with docker run bash","Zero",   "No protection"],
        ],
        col_widths=[2.5*cm, 8*cm, 3*cm, 3.5*cm]
    ),
    sp(10),
]

# Recommendation
story += [h2("Recommended Approach for AICyberAuditBox"), hr()]
story += [
    p("Use a <b>multi-stage Docker build with Nuitka</b>:"),
    bullet("Stage 1 (builder): Has Python source + Nuitka → compiles everything"),
    bullet("Stage 2 (final image): Only copies compiled .so binaries from Stage 1"),
    bullet("Source code never exists in the image that gets shipped to the customer"),
    sp(6),
    p("<b>One-liner to explain to mentor:</b>"),
    code("\"We compile Python to native binaries using Nuitka before building\n"
         " the Docker image. The final image contains only compiled .so files,\n"
         " no .py source. Even if someone extracts the Docker image, they get\n"
         " binary machine code — not readable Python.\""),
    sp(10),
]

# Footer
story += [hr()]
story += [Paragraph("AICyberAuditBox — Internal Technical Reference | Confidential",
    ParagraphStyle("footer", fontSize=8, textColor=GREY, alignment=TA_CENTER))]

# ── Build PDF ─────────────────────────────────────────────────────────────────
doc.build(story)
print(f"\n[OK] PDF created: {OUT}")
print(f"     Location: {OUT}")
