# -*- coding: utf-8 -*-
"""Generates AICyberAuditBox_SOP.pdf -- the standing operating procedure.

How the product is put together, and the order things are done in: releasing a
change, answering a support call, and the rules that do not bend. Written to be
followed rather than read once.

The Update Guide is the two double-clicks. This is everything around them.
"""
import os
import subprocess
import time

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "AICyberAuditBox_SOP.pdf")

INK = colors.HexColor("#1a1a1a")
MUTED = colors.HexColor("#5b6472")
RULE = colors.HexColor("#d4d9e0")
BAND = colors.HexColor("#eef2f7")
ACCENT = colors.HexColor("#1f4e79")
GREEN = colors.HexColor("#1d6b3f")
WARN = colors.HexColor("#8a4b08")
STOP = colors.HexColor("#9b2226")

_ss = getSampleStyleSheet()


def _st(name, **kw):
    base = dict(fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK,
                alignment=TA_LEFT)
    base.update(kw)
    return ParagraphStyle(name, parent=_ss["Normal"], **base)


TITLE = _st("t", fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=ACCENT)
SUB = _st("sub", fontSize=9.5, leading=13.5, textColor=MUTED)
PART = _st("part", fontName="Helvetica-Bold", fontSize=13.5, leading=18,
           textColor=colors.white, backColor=ACCENT, borderPadding=7,
           spaceBefore=13, spaceAfter=8)
STEP = _st("step", fontName="Helvetica-Bold", fontSize=10.5, leading=14,
           textColor=ACCENT, spaceBefore=9, spaceAfter=3)
BODY = _st("b", spaceAfter=4)
NOTE = _st("n", fontSize=8.5, leading=12, textColor=MUTED, spaceAfter=3)
WARNP = _st("w", fontSize=9, leading=12.5, textColor=WARN, spaceAfter=4)
STOPP = _st("s", fontSize=9, leading=12.5, textColor=STOP, spaceAfter=4)
OKP = _st("ok", fontSize=9, leading=12.5, textColor=GREEN, spaceAfter=4)
CODE = _st("c", fontName="Courier", fontSize=8, leading=11.5,
           backColor=BAND, borderPadding=6, spaceBefore=3, spaceAfter=5)
CELL = _st("cell", fontSize=8.5, leading=11.5)
CELLB = _st("cellb", fontName="Helvetica-Bold", fontSize=8.5, leading=11.5)


def table(rows, widths, header=True):
    wrapped = [[Paragraph(c, CELLB if (header and r == 0) else CELL)
                if isinstance(c, str) else c for c in row]
               for r, row in enumerate(rows)]
    t = Table(wrapped, colWidths=widths, hAlign="LEFT", repeatRows=1 if header else 0)
    cmds = [("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, RULE),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5)]
    if header:
        cmds.append(("BACKGROUND", (0, 0), (-1, 0), BAND))
    t.setStyle(TableStyle(cmds))
    return t


def box(n):
    return Paragraph('<font face="Courier" size="11">[ ]</font> <b>%s</b>' % n, CELL)


def git(*args):
    try:
        return subprocess.run(("git",) + args, cwd=ROOT, capture_output=True,
                              text=True, timeout=20).stdout.strip()
    except Exception:
        return ""


def build():
    doc = SimpleDocTemplate(OUT, pagesize=A4,
                            leftMargin=17 * mm, rightMargin=17 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm,
                            title="AICyberAuditBox - Standing Operating Procedure",
                            author="Dhiware Technologies Pvt Ltd")
    s = []

    s.append(Paragraph("AICyberAuditBox &mdash; Standing Operating Procedure", TITLE))
    s.append(Paragraph(
        "How the product is put together, and the order things are done in. "
        "Follow it rather than remember it.", SUB))
    s.append(Spacer(1, 8))

    # =============================================================== 1. shape
    s.append(Paragraph("1 &mdash; How the product is put together", PART))
    s.append(Paragraph(
        "Four images and two volumes. Knowing which of them a change touches is "
        "what decides everything else &mdash; how large the update is, what restarts, "
        "and how long the customer waits.", BODY))
    s.append(table([
        ["Piece", "What is inside", "Changes when"],
        ["<b>app</b><br/>~2.3 GB",
         "The FastAPI application, the browser interface, the Python packages, the "
         "OCR and reranker caches, the ISO report template, and LibreOffice to render "
         "it.",
         "You change code, a package, or the report template. <b>Almost every release.</b>"],
        ["<b>llm</b><br/>~13 GB",
         "llama.cpp, the Gemma 4 12B weights, the embedding model, and the shell "
         "script that decides how the server starts.",
         "Rarely. The weights almost never change; the startup script sometimes does."],
        ["<b>llm-embed</b><br/>0",
         "Nothing of its own. It is the <b>same image</b> as llm under a second name, "
         "started with LLM_MODE=embedding.",
         "Never on its own. It moves whenever llm moves, and must always match it."],
        ["<b>shakthidb</b><br/>~620 MB",
         "PostgreSQL with pgvector, and the schema in init.sql.",
         "Rarely. Schema changes apply themselves at startup."],
        ["<b>redis</b><br/>~58 MB",
         "Stock redis:7-alpine, for live progress on the dashboard.",
         "Never. It is an upstream image."],
    ], [66, 235, 204]))
    s.append(Spacer(1, 4))
    s.append(Paragraph(
        "<b>The customer's data is in neither.</b> Audits, findings, evidence and "
        "uploaded logos live in two Docker volumes (pgdata, app_data), which updates "
        "do not touch. That is why replacing an image is safe, and why a new image "
        "never brings the logos with it &mdash; those are uploaded once, per site.", OKP))

    # ============================================================= 2. release
    s.append(Paragraph("2 &mdash; Releasing a change", PART))
    s.append(Paragraph("Follow in order. Do not start at step 4.", NOTE))
    s.append(table([
        [box("1"), "<b>Make the change and run the tests.</b><br/>"
                   "<font face='Courier' size='8'>python -m pytest</font><br/>"
                   "Green before anything else. A failing suite found here costs "
                   "minutes; found after packaging it costs the whole build."],
        [box("2"), "<b>Commit and push.</b><br/>"
                   "<font face='Courier' size='8'>git push testing Developer:Developer</font><br/>"
                   "Before the build, not after &mdash; this is what lets you answer "
                   "\"what is this customer running?\" later. A previous release shipped "
                   "with no commit representing it and could not be reproduced."],
        [box("3"), "<b>Decide what kind of update this is.</b><br/>"
                   "Changed the application? Option 1. Only how the model server "
                   "starts? Option 2. Unsure? <b>Option 1</b> &mdash; larger and always "
                   "correct."],
        [box("4"), "<b>Build it.</b> Double-click "
                   "<font face='Courier' size='8'>make_update.bat</font>, choose, give "
                   "the next version number. It tests, builds, packages, checksums, "
                   "and copies the applier beside the result."],
        [box("5"), "<b>Send the files and the checksum separately.</b> The files by "
                   "your usual transfer; the checksum in the message. One route "
                   "cannot verify itself."],
        [box("6"), "<b>Confirm it took.</b> Ask the customer for the last line of the "
                   "applier &mdash; it prints the image actually running. Do not treat "
                   "\"it finished\" as confirmation."],
    ], [26, 479], header=False))

    # ============================================================= 3. support
    s.append(PageBreak())
    s.append(Paragraph("3 &mdash; When a customer reports a problem", PART))
    s.append(table([
        [box("1"), "<b>Get the version first.</b><br/>"
                   "<font face='Courier' size='8'>docker inspect --format \"{{.Config.Image}}\" aicyberauditbox_app</font><br/>"
                   "Half of all reports are about something already fixed in a build "
                   "they have not applied."],
        [box("2"), "<b>Get the logs, not a description.</b><br/>"
                   "<font face='Courier' size='8'>docker compose logs app --since 30m > logs.txt</font><br/>"
                   "A screenshot shows what happened; the log shows why. Ask for both."],
        [box("3"), "<b>Find the fact before forming a theory.</b> The one costly habit "
                   "on this project is diagnosing from the symptom. A wrong ISO verdict "
                   "took three wrong diagnoses before one query showed the model had "
                   "flipped a value the database held correctly."],
        [box("4"), "<b>Reproduce it here.</b> If it cannot be reproduced, it cannot be "
                   "confirmed fixed."],
        [box("5"), "<b>Fix it, and add a test that fails without the fix.</b> Revert "
                   "the fix, watch the test go red, put it back. A test that passes "
                   "both ways proves nothing."],
        [box("6"), "<b>Release it</b> by section 2."],
    ], [26, 479], header=False))

    # ======================================================= 3b. model swap
    s.append(Paragraph("4 &mdash; Changing a model", PART))
    s.append(Paragraph(
        "Rare, and worth its own procedure because one step of it is easy to miss "
        "and fails silently.", BODY))

    s.append(Paragraph("The completion model (what writes findings)", STEP))
    s.append(Paragraph(
        "Put the new .gguf in the repo root, add it to Dockerfile.llm, and teach "
        "docker/llm-entrypoint.sh to select it. Ship with "
        "<font face='Courier' size='8'>make_update.bat</font> option 3. Nothing else "
        "is affected &mdash; findings are written fresh each run.", BODY))

    s.append(Paragraph("The embedding model (what finds the evidence)", STEP))
    s.append(Paragraph(
        "Same three files, <b>plus one line that matters more than the rest</b>:", BODY))
    s.append(table([
        [box("1"), "New .gguf in the repo root; add it to <font face='Courier' size='8'>Dockerfile.llm</font>."],
        [box("2"), "Update <font face='Courier' size='8'>docker/llm-entrypoint.sh</font> &mdash; it names the "
                   "embedding file explicitly in the LLM_MODE=embedding branch."],
        [box("3"), "<b>Bump <font face='Courier' size='8'>EMBEDDING_MODEL_ID</font></b> in the app service of "
                   "<font face='Courier' size='8'>docker-compose.customer.yml</font>. Any new value will do; it "
                   "only has to differ."],
        [box("4"), "Ship with <font face='Courier' size='8'>make_update.bat</font> option 3 "
                   "(~13 GB &mdash; the weights live in the image)."],
    ], [26, 479], header=False))

    s.append(Paragraph(
        "<b>Why step 3 is the one to get right.</b> A vector means something only "
        "beside other vectors from the same model. Change the model without changing "
        "that line and the system goes on reusing the previous model's vectors: "
        "similarity still returns a number, retrieval still returns passages, and they "
        "are the wrong ones. No error, no warning &mdash; findings quietly drawn from "
        "evidence that never matched the question. The declared width does not protect "
        "you either: both vector tables are 768 wide, so another 768-wide model is "
        "accepted without complaint.", STOPP))
    s.append(Paragraph(
        "With the line changed, the installation notices at startup, retires the old "
        "vectors and rebuilds them against the new model, saying so in the log:", BODY))
    s.append(Paragraph(
        "[VEC SEARCH] embedding model changed (old -&gt; new); cleared the vector<br/>"
        "index so it rebuilds against the new model.", CODE))
    s.append(Paragraph(
        "The first audit afterwards is slower while documents re-embed. Audits, "
        "findings, evidence, reports and the documents themselves are untouched &mdash; "
        "only the search index is rebuilt.", OKP))

    # =============================================================== 4. rules
    s.append(Paragraph("5 &mdash; Rules that do not bend", PART))
    s.append(table([
        ["#", "Rule", "Why"],
        ["1", "Push only to the <b>testing</b> remote, branch <b>Developer</b>.",
         "Five other remotes are configured and none of them is the product. A push "
         "to the wrong one is quiet and hard to undo."],
        ["2", "Never commit model weights, bundles, dist/, build/, .env, or client "
              "documents. Stage files by name.",
         "<font face='Courier' size='8'>git add -A</font> has swept in a real client's "
         "audit document twice."],
        ["3", "The database password is set <b>before</b> the first install and can "
              "never be changed.",
         "PostgreSQL writes it into the data volume on first start. Changing it later "
         "leaves a database nothing can log in to."],
        ["4", "When editing a customer's configuration, change only the lines for the "
              "component being updated.",
         "The model server appears twice under two names and both must match. A "
         "find-and-replace on the version number stops the product starting."],
        ["5", "Confirm an update by what is <b>running</b>, never by what the restart "
              "reported.",
         "<font face='Courier' size='8'>docker compose up</font> reports success "
         "whether or not the configuration change saved."],
        ["6", "Never change more than one scope mode at a time (Checklist, Control, "
              "Selective).",
         "They share the scope builder, the worker and the validator. Gate every "
         "change and add a test pinning the modes you did not mean to touch."],
        ["7", "A prompt change must be confirmed by a live run, not unit tests alone.",
         "Adding one instruction to the Checklist prompt once inverted verdicts: the "
         "model stopped re-reading the evidence and answered \"no\" on a compliant host."],
    ], [14, 235, 256]))

    # ============================================================ 5. hazards
    s.append(PageBreak())
    s.append(Paragraph("6 &mdash; Failures this product has actually had", PART))
    s.append(Paragraph(
        "Each of these shipped. They are listed because they share a shape, and that "
        "shape is worth recognising before writing the next one.", BODY))
    s.append(table([
        ["Pattern", "How it showed up"],
        ["<b>Two paths deriving the same fact differently.</b>",
         "The severity boxes counted a finding as P4 that their own filter could not "
         "find, because one accepted \"p4\" or \"low\" and the other wanted the exact "
         "phrase \"P4 Low\". The ISO report's PDF and Word versions were built by two "
         "separate pieces of code and drifted apart everywhere the template was edited."],
        ["<b>State applied on the way in with nothing to undo it.</b>",
         "A finished scan left the scope panel showing a no-entry cursor and a "
         "\"scan in progress\" badge, on controls that were editable and working. "
         "Both cleared on reload, so neither reproduced for anyone who went looking."],
        ["<b>A check that treats \"look at this\" as \"this failed\".</b>",
         "A Checklist answer reading \"Yes, NTP is enabled and synchronized\" was "
         "published with a NON_COMPLIANT badge against a compliant host, because a "
         "review flag raised by OCR evidence was read as a grounding failure."],
        ["<b>A document pointing at something not shipped.</b>",
         "The install guide inside the bundle told an air-gapped customer to switch to "
         "a model that had been removed from the image. The compose file's error "
         "message named a .env.example the bundle did not contain."],
        ["<b>A guard that cannot see what it is guarding.</b>",
         "The duplicate page-number check read only top-level paragraphs, so it missed "
         "the field nested in a content control and numbered every page twice. The "
         "patch builder checks Python packages but not system packages, so a patch can "
         "ship code whose dependency is absent."],
    ], [150, 355]))
    s.append(Spacer(1, 4))
    s.append(Paragraph(
        "<b>What they have in common:</b> in every case the product kept working and "
        "looked wrong, or looked right and was wrong. None of them crashed. That is "
        "why the tests for them assert on agreement between two paths, rather than on "
        "one path's output.", WARNP))

    # ========================================================== 6. quick ref
    s.append(Paragraph("7 &mdash; Quick reference", PART))
    s.append(table([
        ["To...", "Run"],
        ["Run the tests", "<font face='Courier' size='8'>python -m pytest</font>"],
        ["Build an update to send",
         "<font face='Courier' size='8'>make_update.bat</font>  (double-click)"],
        ["Build a full bundle / first install",
         "<font face='Courier' size='8'>make_bundle.bat</font>  (double-click)"],
        ["Push your work",
         "<font face='Courier' size='8'>git push testing Developer:Developer</font>"],
        ["See what a site is running",
         "<font face='Courier' size='8'>docker inspect --format \"{{.Config.Image}}\" aicyberauditbox_app</font>"],
        ["Read a site's logs",
         "<font face='Courier' size='8'>docker compose logs app --since 30m</font>"],
        ["Check the LLM sized itself correctly",
         "<font face='Courier' size='8'>docker compose logs llm | findstr \"LLM ENTRYPOINT\"</font><br/>"
         "last line must read <font face='Courier' size='8'>= 32768 tokens per request</font>"],
        ["Find a site's configuration file",
         "<font face='Courier' size='8'>docker compose ls</font>"],
    ], [150, 355]))

    s.append(Spacer(1, 8))
    s.append(Paragraph(
        "Dhiware Technologies Pvt Ltd &middot; %s &middot; repository at %s. "
        "Companion documents: the Update Guide (the two double-clicks) and the Release "
        "Handbook (the reasoning and the alternatives)."
        % (time.strftime("%d %B %Y"), git("rev-parse", "--short", "HEAD") or "unknown"),
        NOTE))

    doc.build(s)
    print("Wrote " + OUT)


if __name__ == "__main__":
    build()
