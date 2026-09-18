# -*- coding: utf-8 -*-
"""Generates AICyberAuditBox_3.25_Handover_Checklist.pdf.

Two audiences in one document, deliberately separated:

  Part A  what the person shipping the bundle must do first
  Part B  text that can be pasted straight into the covering note to the site

Part B exists because the guide inside the bundle does not mention the database
password or the first-login procedure, and a site with no internet cannot look
either of them up.

Reads the bundle's size and checksum from disk when they are available, so the
document cannot quote figures the artifact outgrew.
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
OUT = os.path.join(ROOT, "AICyberAuditBox_3.25_Handover_Checklist.pdf")
BUNDLE = os.path.join(os.path.dirname(ROOT), "customer_deployment_package",
                      "v3.25", "AICyberAuditBox-3.25-complete.tar")

INK = colors.HexColor("#1a1a1a")
MUTED = colors.HexColor("#5b6472")
RULE = colors.HexColor("#d4d9e0")
BAND = colors.HexColor("#f2f4f7")
ACCENT = colors.HexColor("#1f4e79")
WARN = colors.HexColor("#8a4b08")
STOP = colors.HexColor("#9b2226")
OK = colors.HexColor("#1d6b3f")

_ss = getSampleStyleSheet()


def _st(name, **kw):
    base = dict(fontName="Helvetica", fontSize=9.5, leading=13.5,
                textColor=INK, alignment=TA_LEFT)
    base.update(kw)
    return ParagraphStyle(name, parent=_ss["Normal"], **base)


TITLE = _st("t", fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=ACCENT)
SUB = _st("sub", fontSize=9.5, leading=13.5, textColor=MUTED)
H1 = _st("h1", fontName="Helvetica-Bold", fontSize=13, leading=16.5, textColor=ACCENT,
         spaceBefore=13, spaceAfter=4)
H2 = _st("h2", fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=INK,
         spaceBefore=9, spaceAfter=3)
BODY = _st("b", spaceAfter=4)
NOTE = _st("n", fontSize=8.5, leading=12, textColor=MUTED)
WARNP = _st("w", fontSize=9.5, leading=13, textColor=WARN, spaceAfter=4)
STOPP = _st("s", fontSize=9.5, leading=13, textColor=STOP, spaceAfter=4)
CODE = _st("c", fontName="Courier", fontSize=8.5, leading=12,
           backColor=BAND, borderPadding=6, spaceBefore=4, spaceAfter=6)
CELL = _st("cell", fontSize=8.5, leading=11.5)
CELLB = _st("cellb", fontName="Helvetica-Bold", fontSize=8.5, leading=11.5)


def table(rows, widths, header=True):
    wrapped = []
    for r, row in enumerate(rows):
        wrapped.append([Paragraph(c, CELLB if (header and r == 0) else CELL)
                        if isinstance(c, str) else c for c in row])
    t = Table(wrapped, colWidths=widths, hAlign="LEFT", repeatRows=1 if header else 0)
    cmds = [("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, RULE),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    if header:
        cmds.append(("BACKGROUND", (0, 0), (-1, 0), BAND))
    t.setStyle(TableStyle(cmds))
    return t


def box(label, colour):
    return Paragraph('<font color="%s"><b>%s</b></font>' % (colour.hexval(), label), CELL)


def bundle_facts():
    """Size and checksum straight from the artifact, never typed in by hand."""
    size = "not found"
    if os.path.exists(BUNDLE):
        size = "%.2f GB" % (os.path.getsize(BUNDLE) / 1024.0 ** 3)
    digest = None
    sidecar = BUNDLE + ".sha256"
    if os.path.exists(sidecar):
        raw = open(sidecar, encoding="utf-8-sig").read().split()
        if raw:
            digest = raw[0].strip().lower()
    return size, digest


def build():
    size, digest = bundle_facts()

    doc = SimpleDocTemplate(OUT, pagesize=A4,
                            leftMargin=17 * mm, rightMargin=17 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm,
                            title="AICyberAuditBox 3.25 - Handover Checklist",
                            author="Dhiware Technologies Pvt Ltd")
    s = []

    s.append(Paragraph("AICyberAuditBox 3.25 &mdash; Handover Checklist", TITLE))
    s.append(Paragraph(
        "What to do before the bundle leaves, and what to send with it. "
        "Part B can be pasted straight into the covering note.", SUB))
    s.append(Spacer(1, 9))

    # ------------------------------------------------ the artifact
    s.append(Paragraph("The artifact", H1))
    rows = [["Item", "Value"],
            ["File", "AICyberAuditBox-3.25-complete.tar"],
            ["Location", "Desktop\\Full_audit_box\\customer_deployment_package\\v3.25\\"],
            ["Size", size],
            ["Contents", "5 images (app, llm, llm-embed, shakthidb, redis), verified present "
                         "by manifest &middot; docker-compose.yml pinned to 3.25 &middot; "
                         "install.sh &middot; install.bat &middot; INSTALL_v3.25.md"],
            ["Model", "Gemma 4 12B Q8_0 only. The E4B fallback was removed from this build."]]
    if digest:
        rows.append(["SHA-256", "<font face='Courier' size='7'>%s</font>" % digest])
    s.append(table(rows, [62, 442]))

    # ------------------------------------------------ PART A
    s.append(Paragraph("Part A &mdash; before the bundle leaves", H1))
    s.append(table([
        ["", "Do this", "Why"],
        [box("BLOCKER", STOP), "<b>Install it once yourself, on a clean machine.</b> "
         "Extract, run the installer, log in, run one small audit end to end.",
         "<b>This bundle has never been booted.</b> Its contents are verified; its behaviour is "
         "not. A site with no internet cannot be remotely debugged, and three separate "
         "'points at something that is not shipped' defects were found in this bundle's own "
         "files while preparing it. Assume a fourth until a real install proves otherwise."],
        [box("BLOCKER", STOP), "<b>Commit and tag the source at 3.25.</b>",
         "Nothing that produced this tar is in git. This has already cost this project once "
         "&mdash; the note in CLAUDE.md reads <i>'no commit represents the shipped v3.23'</i>, "
         "and the standing rule is to tag every release. Without a tag, a support call about "
         "3.25 cannot be answered from the repository."],
        [box("BLOCKER", STOP), "<b>Send the SHA-256 separately from the tar.</b>"
         + ("" if digest else " Generate it first."),
         "14 GB over USB or a network share can corrupt silently, and the failure would surface "
         "as a strange runtime fault rather than an obvious one. A checksum sent by the same "
         "medium as the file proves nothing &mdash; send it by mail or message."],
        [box("DO", OK), "Record what shipped: version, git SHA, checksum, date, and the "
                        "customer's sizing.",
         "The runtime limits are pinned per customer at bundle time. Six months from now this "
         "is the only way to know which limits this site actually received."],
    ], [58, 166, 280]))

    # ------------------------------------------------ PART B
    s.append(PageBreak())
    s.append(Paragraph("Part B &mdash; what to send the customer", H1))
    s.append(Paragraph(
        "Everything below has to be in the covering note, because the guide inside the bundle "
        "does not carry it and the site has no internet to look it up.", WARNP))

    s.append(Paragraph("Prerequisite", H2))
    s.append(Paragraph(
        "Docker installed. Nothing else. No internet is needed at any point, during install "
        "or afterwards.", BODY))

    s.append(Paragraph("Installation", H2))
    s.append(Paragraph(
        "tar -xf AICyberAuditBox-3.25-complete.tar<br/>"
        "cd AICyberAuditBox-3.25<br/>"
        "echo 'POSTGRES_PASSWORD=ChooseAStrongPasswordHere' &gt; .env<br/>"
        "./install.sh", CODE))
    s.append(Paragraph(
        "On Windows: create <font face='Courier' size='8.5'>.env</font> in Notepad as a single "
        "line, save it beside <font face='Courier' size='8.5'>docker-compose.yml</font>, then "
        "run <font face='Courier' size='8.5'>install.bat</font>.", NOTE))
    s.append(Paragraph(
        "<b>The .env step must come before the installer, and the password can never be "
        "changed afterwards.</b> PostgreSQL writes it into the data volume on first start; "
        "changing it later leaves a database nothing can log in to. Tell them to record it "
        "somewhere permanent before they run anything.", STOPP))

    s.append(Paragraph("First login &mdash; the step most likely to strand them", H2))
    s.append(Paragraph(
        "The username is <b>admin</b>. The password is <b>randomly generated and printed to "
        "the application log exactly once</b>, marked <i>'SAVE THIS NOW, it will not be shown "
        "again'</i>. It cannot be set in advance &mdash; the shipped compose file does not pass "
        "that variable through. Immediately after the installer finishes:", BODY))
    s.append(Paragraph(
        'docker compose logs app | grep -A2 "generated a random admin password"', CODE))
    s.append(Paragraph(
        "If that line is missed, the practical recovery is to destroy the database volume and "
        "install again. At first login the interface shows a QR code to scan into an "
        "authenticator app, which supplies the one-time code for every later sign-in.", BODY))

    s.append(Paragraph("Hardware &mdash; a floor, not a recommendation", H2))
    s.append(Paragraph(
        "The 12B model needs <b>12.5 GB resident</b> before a single audit slot: roughly 17 GB "
        "for two concurrent auditors, and a 32 GB host as the practical minimum. On Docker "
        "Desktop the figure that matters is the <b>virtual machine's</b> memory allowance, not "
        "the machine's RAM &mdash; a 32 GB laptop commonly gives Docker about 16 GB.", BODY))
    s.append(Paragraph(
        "This build ships no smaller model, so there is nothing to fall back to. If memory is "
        "short the LLM container <b>refuses to start</b> and prints the three numbers involved, "
        "rather than being killed partway through an audit. That refusal is correct behaviour, "
        "not a fault.", WARNP))

    s.append(Paragraph("What normal looks like", H2))
    s.append(table([
        ["Point", "Expected"],
        ["First start", "3&ndash;5 minutes while 11.8 GB of weights load. The application "
                        "answering 502 during that window is normal."],
        ["Success check", "The installer prints the LLM's last line. It must read "
                          "<font face='Courier' size='8'>= 32768 tokens per request</font>. "
                          "<b>A lower number means evidence is being truncated before the model "
                          "sees it, and findings will be wrong.</b> This is the one line worth "
                          "checking on every restart."],
        ["Ports", "8000 application &middot; 15234 database &middot; 11434 / 11435 LLM"],
        ["Licensing", "Nothing to install. Entitlement enforcement is off in this build."],
    ], [62, 442]))

    # ------------------------------------------------ known gaps
    s.append(Paragraph("Known gaps in this bundle", H1))
    s.append(Paragraph(
        "Stated plainly so they are decisions rather than surprises. None of them prevent a "
        "working installation; all of them are worth closing before the next one.", BODY))
    s.append(table([
        ["Gap", "Consequence", "Fix for next build"],
        ["The shipped guide never mentions <font face='Courier' size='8'>.env</font> or "
         "<font face='Courier' size='8'>POSTGRES_PASSWORD</font>",
         "Following the guide alone, the install stops at the first command with an error "
         "naming a file (<font face='Courier' size='8'>.env.example</font>) that is not in "
         "the bundle.",
         "Have the installers generate <font face='Courier' size='8'>.env</font> with a random "
         "password when absent, ship <font face='Courier' size='8'>.env.example</font>, and "
         "document it. The customer would then do nothing."],
        ["No checksum inside the bundle",
         "Integrity depends on a value sent separately, by hand.",
         "Have the bundler emit the SHA-256 and a manifest, and have the installer verify "
         "before extracting."],
        ["Source ships readable",
         "This build is the uncompiled variant, so the Python source is present in the image.",
         "The Nuitka path exists and is wired to a build flag, but has never been built. It "
         "verifies itself at build time and must be proven once before it is used."],
    ], [128, 190, 186]))

    s.append(Spacer(1, 10))
    s.append(Paragraph(
        "Dhiware Technologies Pvt Ltd &middot; prepared %s &middot; figures read from the "
        "artifact on disk." % time.strftime("%d %B %Y"), NOTE))

    doc.build(s)
    print("Wrote " + OUT)
    print("checksum included: " + ("yes" if digest else "NO -- sidecar not ready"))


if __name__ == "__main__":
    build()
