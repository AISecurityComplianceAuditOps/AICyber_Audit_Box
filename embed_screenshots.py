# -*- coding: utf-8 -*-
"""
Add the 3 real screenshots into the PPTX as dedicated slides with annotations.
"""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

IN  = r"samples/AICyberAuditOPS Sample Data/AICyberAuditBox_Presentation_Updated.pptx"
OUT = r"samples/AICyberAuditOPS Sample Data/AICyberAuditBox_Presentation_Updated.pptx"

SCREENSHOTS = [
    {
        "path": r"C:\Users\veeresh988V\.gemini\antigravity-ide\brain\d3ebc255-9c7e-4466-9ced-3ea150284ee3\media__1788716048745.png",
        "title": "Screenshot 1: PQC Finding Detail View",
        "subtitle": "Detailed quantum-vulnerability finding for NGINX — ECDSA algorithm",
        "callouts": [
            ("Target Host & Scope",         0.07, 0.06),
            ("OWASP + Risk Category",       0.07, 0.14),
            ("CIA Impact",                  0.07, 0.22),
            ("Quantum Readiness Badge",     0.07, 0.30),
            ("Attack Vector",               0.07, 0.38),
            ("Risk Score: 84/100 CRITICAL", 0.07, 0.46),
            ("Proof of Concept Output",     0.07, 0.55),
            ("Asset Category (OEM)",        0.07, 0.63),
        ],
        "insert_after": 3,  # after slide index 3 (slide 4)
    },
    {
        "path": r"C:\Users\veeresh988V\.gemini\antigravity-ide\brain\d3ebc255-9c7e-4466-9ced-3ea150284ee3\media__1788716048770.png",
        "title": "Screenshot 2: Scan Workspace — Upload & Configure",
        "subtitle": "File upload + PQC Framework control selection with AI Auto-Scoping",
        "callouts": [
            ("File Upload / Evidence Collector", 0.07, 0.06),
            ("Already Attached Files",           0.07, 0.18),
            ("Target Framework: PQC",            0.07, 0.30),
            ("AI Auto-Scoping Active",           0.07, 0.42),
            ("12/12 Controls Selected",          0.07, 0.54),
            ("Run Audit Scan Button",            0.07, 0.66),
        ],
        "insert_after": 4,
    },
    {
        "path": r"C:\Users\veeresh988V\.gemini\antigravity-ide\brain\d3ebc255-9c7e-4466-9ced-3ea150284ee3\media__1788716048779.png",
        "title": "Screenshot 3: Audit Records & OEM Readiness Matrix",
        "subtitle": "Compliance summary with QBOM and OEM Asset Category — the column your mentor flagged",
        "callouts": [
            ("Compliance Summary (0 Compliant, 11 Non-Compliant)", 0.07, 0.06),
            ("ShakthiDB Audit Ledger — Cryptographically Locked",  0.07, 0.14),
            ("QBOM: All vulnerable algorithms listed",             0.07, 0.22),
            ("OEM Readiness Matrix",                               0.07, 0.30),
            ("Asset Category Column (Load Balancer / Database)",   0.07, 0.38),
            ("PQC-2 Finding (Non-Compliant P1 Critical)",          0.07, 0.46),
        ],
        "insert_after": 5,
    },
]

C_DARK  = RGBColor(0x1a, 0x1a, 0x2e)
C_BLUE  = RGBColor(0x0f, 0x34, 0x60)
C_WHITE = RGBColor(0xff, 0xff, 0xff)
C_GREY  = RGBColor(0x7f, 0x8c, 0x8d)
C_ACCNT = RGBColor(0x27, 0xae, 0xc0)
C_YEL   = RGBColor(0xff, 0xd7, 0x00)
C_RED   = RGBColor(0xe9, 0x45, 0x60)

W = Inches(13.333)
H = Inches(7.5)

def add_rect(slide, l, t, w, h, fill_rgb):
    shape = slide.shapes.add_shape(1, l, t, w, h)
    shape.line.fill.background()
    shape.line.width = 0
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_rgb
    return shape

def add_text(slide, text, l, t, w, h,
             font_size=11, bold=False, color=C_WHITE,
             align=PP_ALIGN.LEFT, wrap=True, italic=False, font_name="Calibri"):
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

prs = Presentation(IN)
blank_layout = prs.slide_layouts[6]

# We'll collect slides to insert (in reverse order so indices stay valid)
inserts = []  # list of (insert_after_index, slide_object)

for sc in SCREENSHOTS:
    # Create new slide
    new_slide_xml = prs.slide_layouts[6]._element
    new_slide = prs.slides.add_slide(blank_layout)

    # Background
    add_rect(new_slide, 0, 0, W, H, C_DARK)
    # Header bar
    add_rect(new_slide, 0, 0, W, Inches(0.85), C_BLUE)

    # Title
    add_text(new_slide, sc["title"],
             Inches(0.3), Inches(0.08), Inches(11), Inches(0.55),
             font_size=20, bold=True, color=C_WHITE)
    # Subtitle
    add_text(new_slide, sc["subtitle"],
             Inches(0.3), Inches(0.62), Inches(11.5), Inches(0.3),
             font_size=10, color=RGBColor(0xae, 0xd6, 0xf1), italic=True)

    # Screenshot image — center, large
    # Leave left panel for callouts, right 9.5" for screenshot
    CALLOUT_W = Inches(3.0)
    IMG_X     = Inches(3.2)
    IMG_Y     = Inches(0.95)
    IMG_W     = Inches(9.9)
    IMG_H     = Inches(6.35)

    # Add screenshot image
    try:
        new_slide.shapes.add_picture(sc["path"], IMG_X, IMG_Y, IMG_W, IMG_H)
        print(f"  [OK] Screenshot embedded: {sc['path'].split(chr(92))[-1]}")
    except Exception as e:
        print(f"  [!] Could not embed screenshot: {e}")

    # Left callout panel background
    add_rect(new_slide, 0, Inches(0.95), Inches(3.1), Inches(6.35),
             RGBColor(0x0a, 0x25, 0x45))

    add_text(new_slide, "KEY AREAS:",
             Inches(0.15), Inches(1.0), Inches(2.7), Inches(0.3),
             font_size=9, bold=True, color=C_YEL)

    # Callouts — evenly spaced on left panel
    num = len(sc["callouts"])
    spacing = 5.6 / max(num, 1)
    for i, (label, _, _) in enumerate(sc["callouts"]):
        y = Inches(1.35 + i * spacing)
        # Bullet dot
        add_rect(new_slide, Inches(0.18), y + Inches(0.07), Inches(0.12), Inches(0.12), C_RED)
        # Label text
        add_text(new_slide, label,
                 Inches(0.38), y, Inches(2.6), Inches(0.5),
                 font_size=9, color=C_WHITE, wrap=True, bold=False)

    # Footer
    add_text(new_slide, "Proprietary and Confidential | DhiWare Technologies Pvt Ltd",
             Inches(0.3), Inches(7.15), Inches(12), Inches(0.3),
             font_size=8, color=C_GREY, align=PP_ALIGN.CENTER)

    inserts.append(sc["insert_after"])


# ── Reorder slides: move the last 3 added slides to their correct positions ──
# Slides were appended at end: indices 8, 9, 10 (0-based)
# We need to move them to after slides 3, 4, 5 respectively
# 
# Strategy: we reorder by manipulating the slide list XML directly
from pptx.oxml.ns import qn as _qn

def move_slide(prs, old_index, new_index):
    """Move slide at old_index to new_index."""
    xml_slides = prs.slides._sldIdLst
    slides = list(xml_slides)
    if old_index == new_index:
        return
    slide_to_move = slides[old_index]
    xml_slides.remove(slide_to_move)
    slides.pop(old_index)
    if new_index > old_index:
        new_index -= 1
    slides.insert(new_index, slide_to_move)
    xml_slides.clear()
    for s in slides:
        xml_slides.append(s)

total = len(prs.slides)
print(f"\nTotal slides before reorder: {total}")
for i, slide in enumerate(prs.slides):
    for shape in slide.shapes:
        if shape.has_text_frame:
            t = shape.text_frame.text[:60].strip()
            if t:
                print(f"  [{i}] {t[:70]}")
                break

# Screenshot slides are at indices 8, 9, 10
# Target positions:
#   Screenshot 1 (currently 8) -> after slide 4 (Workflow) = position 5
#   Screenshot 2 (currently 9) -> after slide 6 (Asset Category) = position 7
#   Screenshot 3 (currently 10) -> after slide 8 = position 9

# Move screenshot 1 from index 8 -> index 4 (after slide index 3 = 4th slide)
move_slide(prs, 8, 4)
# Now screenshot 2 is at index 9, move to index 7 (after slide 6)
move_slide(prs, 9, 7)
# Now screenshot 3 is at index 10, move to index 10 (after slide 9)
move_slide(prs, 10, 10)

print(f"\nTotal slides after reorder: {len(prs.slides)}")
for i, slide in enumerate(prs.slides):
    for shape in slide.shapes:
        if shape.has_text_frame:
            t = shape.text_frame.text[:70].strip()
            if t:
                print(f"  [{i+1}] {t[:70]}")
                break

prs.save(OUT)
print(f"\n[OK] Updated PPTX saved: {OUT}")
