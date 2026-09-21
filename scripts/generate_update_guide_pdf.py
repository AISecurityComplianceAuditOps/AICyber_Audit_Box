# -*- coding: utf-8 -*-
"""Generates AICyberAuditBox_Update_Guide.pdf.

Two double-clicks: one to build an update, one to apply it. This describes what
they do, what to choose, and the few things still worth a human's attention.

An earlier version of this document was a page of commands for each side. Every
one of those steps went wrong in the field at least once, which is why the
scripts exist and why this is now mostly prose.
"""
import os
import time

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "AICyberAuditBox_Update_Guide.pdf")

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
    base = dict(fontName="Helvetica", fontSize=10, leading=14, textColor=INK,
                alignment=TA_LEFT)
    base.update(kw)
    return ParagraphStyle(name, parent=_ss["Normal"], **base)


TITLE = _st("t", fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=ACCENT)
SUB = _st("sub", fontSize=10, leading=14, textColor=MUTED)
PART = _st("part", fontName="Helvetica-Bold", fontSize=14, leading=18,
           textColor=colors.white, backColor=ACCENT, borderPadding=7,
           spaceBefore=13, spaceAfter=8)
STEP = _st("step", fontName="Helvetica-Bold", fontSize=11, leading=15,
           textColor=ACCENT, spaceBefore=9, spaceAfter=3)
BODY = _st("b", spaceAfter=4)
NOTE = _st("n", fontSize=9, leading=12.5, textColor=MUTED, spaceAfter=3)
WARNP = _st("w", fontSize=9.5, leading=13, textColor=WARN, spaceAfter=4)
STOPP = _st("s", fontSize=9.5, leading=13, textColor=STOP, spaceAfter=4)
OKP = _st("ok", fontSize=10, leading=14, textColor=GREEN, spaceAfter=4)
BIG = _st("big", fontName="Courier-Bold", fontSize=12, leading=17,
          backColor=BAND, borderPadding=8, spaceBefore=4, spaceAfter=7)
CODE = _st("c", fontName="Courier", fontSize=8.5, leading=12.5,
           backColor=BAND, borderPadding=7, spaceBefore=3, spaceAfter=6)
CELL = _st("cell", fontSize=9, leading=12)
CELLB = _st("cellb", fontName="Helvetica-Bold", fontSize=9, leading=12)


def table(rows, widths, header=True):
    wrapped = [[Paragraph(c, CELLB if (header and r == 0) else CELL)
                if isinstance(c, str) else c for c in row]
               for r, row in enumerate(rows)]
    t = Table(wrapped, colWidths=widths, hAlign="LEFT", repeatRows=1 if header else 0)
    cmds = [("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, RULE),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]
    if header:
        cmds.append(("BACKGROUND", (0, 0), (-1, 0), BAND))
    t.setStyle(TableStyle(cmds))
    return t


def build():
    doc = SimpleDocTemplate(OUT, pagesize=A4,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm,
                            title="AICyberAuditBox - Update Guide",
                            author="Dhiware Technologies Pvt Ltd")
    s = []

    s.append(Paragraph("AICyberAuditBox &mdash; Update Guide", TITLE))
    s.append(Paragraph(
        "Two double-clicks: one to build an update, one to apply it.", SUB))
    s.append(Spacer(1, 8))

    s.append(table([
        ["", "You run", "The customer runs"],
        ["Update an existing site",
         "<font face='Courier' size='9'><b>make_update.bat</b></font>",
         "<font face='Courier' size='9'><b>apply_update.bat</b></font>"],
        ["LLM startup settings only",
         "<font face='Courier' size='9'><b>make_update.bat</b></font> &rarr; option 2",
         "<font face='Courier' size='9'><b>apply_llm_config.bat</b></font>"],
        ["First installation",
         "<font face='Courier' size='9'><b>make_bundle.bat</b></font>",
         "<font face='Courier' size='9'><b>install.bat</b></font>"],
    ], [128, 190, 187]))

    # ================================================================== PART A
    s.append(Paragraph("PART A &mdash; Build the update (you)", PART))
    s.append(Paragraph("Double-click <font face='Courier' size='10'>make_update.bat</font> "
                       "and answer two questions.", BODY))

    s.append(Paragraph("Question 1: what changed?", STEP))
    s.append(table([
        ["", "Choose this when you changed...", "Size"],
        ["1", "Application code, a Python package, a system package, or the "
              "report template. <b>The usual answer.</b>", "~2.3 GB"],
        ["2", "Only how the model server starts &mdash; threads, slots, context "
              "size, which model is served.", "<b>~10 KB</b>"],
        ["3", "The model weights themselves (a different .gguf).", "~13 GB"],
        ["4", "The database image &mdash; init.sql or Postgres itself.", "~620 MB"],
        ["5", "Everything, or this is a new site with nothing installed.", "~14 GB"],
    ], [16, 420, 69]))
    s.append(Paragraph(
        "<b>If you are unsure between 1 and 2, choose 1.</b> It is larger and always "
        "correct; option 2 only carries the startup script.", NOTE))

    s.append(Paragraph("Question 2: the version number", STEP))
    s.append(Paragraph(
        "It shows the current one and you give the next. Always go up &mdash; reusing a "
        "number leaves two different builds sharing a name, and nothing afterwards can "
        "tell them apart.", BODY))

    s.append(Paragraph("What it does", STEP))
    s.append(Paragraph(
        "Runs the test suite (option 1), builds, packages, writes a SHA-256, and copies "
        "the matching applier beside the result. It stops at the first failure, so a "
        "red test suite never becomes an artifact on its way to a customer. Everything "
        "lands in <font face='Courier' size='8.5'>..\\customer_deployment_package\\v&lt;version&gt;\\</font>, "
        "and the last thing it prints is the list of files to send.", BODY))

    s.append(Paragraph("Send the checksum in your message as well", STEP))
    s.append(Paragraph(
        "It travels beside the file already. A checksum that arrives only by the same "
        "route as the thing it vouches for proves nothing &mdash; whatever damaged or "
        "replaced one could do the same to the other.", WARNP))

    # ================================================================== PART B
    s.append(PageBreak())
    s.append(Paragraph("PART B &mdash; Apply the update (the customer)", PART))
    s.append(Paragraph(
        "Send them these words. There is one instruction.", BODY))
    s.append(Paragraph("Put all the files in one folder and double-click "
                       "apply_update.bat", BIG))
    s.append(Paragraph(
        "It works out which component the update is for and which version, from the "
        "file itself. Nothing to choose, nothing to type, nothing to edit.", BODY))

    s.append(Paragraph("What they will see", STEP))
    s.append(table([
        ["Step", "What happens"],
        ["1", "Checks Docker is running, and says so plainly if it is not."],
        ["2", "Verifies the download against its checksum, and refuses to go further "
              "if the file is damaged."],
        ["3", "Loads the image. Several minutes, printing nothing &mdash; this is normal."],
        ["4", "Finds their installation by asking Docker where the running system was "
              "started from, backs the configuration up, and changes only the lines "
              "this update owns."],
        ["5", "Restarts only what changed, then confirms the new version is the one "
              "actually running."],
    ], [32, 473]))

    s.append(Paragraph("Why step 5 is the one that matters", STEP))
    s.append(Paragraph(
        "Restarting reports success whether or not the configuration change saved, so a "
        "half-applied update looks identical to a finished one. The script therefore "
        "asks the running container what it is actually built from, and will not call "
        "the update done until that matches.", BODY))

    s.append(Paragraph("If something goes wrong", STEP))
    s.append(Paragraph(
        "It stops, says what happened in one sentence, and tells them whether anything "
        "was changed. If the configuration had already been updated, it prints the two "
        "commands that put it back. The previous version's image is still on the "
        "machine, so rolling back takes seconds and loses nothing.", BODY))
    s.append(Paragraph(
        "It never leaves an update half-applied: if the configuration cannot be changed "
        "correctly, it restores the backup before stopping.", OKP))

    s.append(Paragraph("The one thing to warn them about", STEP))
    s.append(Paragraph(
        "If they ever edit the configuration by hand instead, they must change only the "
        "line for the component being updated. The model server appears twice, under "
        "two names, and both must match each other &mdash; a find-and-replace on the bare "
        "version number rewrites lines naming images their machine does not have, and "
        "the product will not start. The script does this correctly and checks itself "
        "afterwards; a person doing it by hand has already got it wrong once.", STOPP))

    # ================================================================== PART C
    s.append(PageBreak())
    s.append(Paragraph("Option 2, and why it exists", PART))
    s.append(Paragraph(
        "Changing how the model server starts &mdash; how many requests it serves at "
        "once, how much context each gets, which model it loads &mdash; is a few "
        "kilobytes of shell script. But that script lives inside an image carrying "
        "12.6 GB of model weights, so sending \"the new image\" means sending the "
        "weights again, unchanged.", BODY))
    s.append(Paragraph(
        "Option 2 sends the script and the recipe instead. The customer's machine "
        "rebuilds its own LLM image on top of the one it already has, inheriting the "
        "weights untouched. Seconds, entirely offline, and about ten kilobytes on the "
        "wire.", OKP))
    s.append(Paragraph(
        "They double-click <font face='Courier' size='9'>apply_llm_config.bat</font>. It "
        "finds their current version, rebuilds, moves both model-server names together, "
        "restarts them, and confirms. It picks the new version number itself.", BODY))
    s.append(Paragraph(
        "Afterwards the model reloads, so they should allow 3&ndash;5 minutes before "
        "running an audit &mdash; and check the sizing line, which is what tells you the "
        "machine has the memory the settings assume:", BODY))
    s.append(Paragraph(
        "docker compose logs llm | findstr \"LLM ENTRYPOINT\"", CODE))
    s.append(Paragraph(
        "The last line must read <font face='Courier' size='8.5'>= 32768 tokens per "
        "request</font>. A lower number means evidence is being truncated before the "
        "model sees it, and findings will be unreliable.", WARNP))

    s.append(Paragraph("What is still manual", PART))
    s.append(table([
        ["Task", "Why it is not automated"],
        ["Sending the files", "Your transfer medium, your call."],
        ["First installation", "There is nothing to update yet. Full bundle, "
                              "install.bat, and a database password chosen before "
                              "install that can never be changed afterwards."],
        ["Deciding which option", "Only you know what you changed. When unsure, the "
                                 "larger option is always correct."],
    ], [110, 395]))

    s.append(Spacer(1, 10))
    s.append(Paragraph(
        "Dhiware Technologies Pvt Ltd &middot; %s &middot; the Release Handbook covers "
        "the reasoning and the failure modes behind these steps."
        % time.strftime("%d %B %Y"), NOTE))

    doc.build(s)
    print("Wrote " + OUT)


if __name__ == "__main__":
    build()
