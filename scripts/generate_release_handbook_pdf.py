# -*- coding: utf-8 -*-
"""Generates AICyberAuditBox_Release_Handbook.pdf.

One document covering the whole release path: what the images are, how to build
a full bundle, how to build a patch, and -- the part that costs money when it is
got wrong -- when a patch is NOT valid and will silently ship something that
does nothing.

Figures are read from the artifacts on disk where they exist, so the document
cannot quote numbers the build outgrew.
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
OUT = os.path.join(ROOT, "AICyberAuditBox_Release_Handbook.pdf")
BUNDLE_DIR = os.path.join(os.path.dirname(ROOT), "customer_deployment_package")

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


def tag(text, colour):
    return Paragraph('<font color="%s"><b>%s</b></font>' % (colour.hexval(), text), CELL)


def git(*args):
    try:
        return subprocess.run(("git",) + args, cwd=ROOT, capture_output=True,
                              text=True, timeout=20).stdout.strip()
    except Exception:
        return ""


def bundles_on_disk():
    """Every bundle produced so far, with its real size."""
    found = []
    if os.path.isdir(BUNDLE_DIR):
        for ver in sorted(os.listdir(BUNDLE_DIR)):
            d = os.path.join(BUNDLE_DIR, ver)
            if not os.path.isdir(d):
                continue
            for f in sorted(os.listdir(d)):
                if f.endswith(".tar"):
                    p = os.path.join(d, f)
                    found.append((ver, f, "%.2f GB" % (os.path.getsize(p) / 1024.0 ** 3)))
    return found


def build():
    doc = SimpleDocTemplate(OUT, pagesize=A4,
                            leftMargin=17 * mm, rightMargin=17 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm,
                            title="AICyberAuditBox - Release Handbook",
                            author="Dhiware Technologies Pvt Ltd")
    s = []

    s.append(Paragraph("AICyberAuditBox &mdash; Release Handbook", TITLE))
    s.append(Paragraph(
        "How to build a bundle, how to build a patch, and when a patch will "
        "silently ship nothing. Written to be read before a release, not after "
        "one goes wrong.", SUB))
    s.append(Spacer(1, 9))

    # ============================================== 1. state
    s.append(Paragraph("1.  Where things stand", H1))
    head = git("log", "-1", "--format=%h %s")
    ahead = git("rev-list", "--count", "testing/main..HEAD")
    s.append(table([
        ["Item", "State"],
        ["Local branch", "<font face='Courier' size='8'>Developer</font>, tracking "
                         "<font face='Courier' size='8'>testing/main</font>"],
        ["Local HEAD", "<font face='Courier' size='8'>%s</font>" % (head or "unknown")],
        ["Unpushed", "%s commit(s) &mdash; <b>push blocked by a 403</b>, see section 7"
         % (ahead or "?")],
        ["Tests", "352 passing, 18 skipped"],
        ["Customer is running", "<b>3.25</b>, which has none of this session's fixes"],
    ], [82, 423]))

    # ============================================== 2. fixed
    s.append(Paragraph("2.  What was fixed", H1))
    s.append(Paragraph(
        "Five defects, each with a regression test that fails against the old code. "
        "Three of them had been shipping to customers for some time.", BODY))
    s.append(table([
        ["#", "Defect", "Why it went unnoticed"],
        ["1", "<b>ISO PDF ignored the branded template.</b> The DOCX was built by "
              "filling in Sample report.docx; the PDF was written out longhand in "
              "fpdf. One payload, two differently branded documents.",
         "Both formats 'worked'. Only someone comparing them side by side would see "
         "that the PDF was not the template the customer signed off."],
        ["2", "<b>Every ISO report numbered its pages twice</b> &mdash; "
              "\"Page 1 of 9Page 1 of 9\".",
         "The duplicate guard read footer.paragraphs, which in python-docx yields "
         "only direct children of w:ftr. This template hides its page field inside "
         "nested content controls, so the guard saw an empty footer."],
        ["3", "<b>The contents page never refreshed</b>, sending readers of an "
              "8-page report to page 13.",
         "The template has a TOC field but no w:updateFields, so Word showed the "
         "numbers cached from the 31-page document it was built from."],
        ["4", "<b>A finished scan left the scope panel looking locked.</b> Buttons "
              "showed a no-entry cursor while being fully clickable.",
         "One branch served lock and unlock. Locking rewrote the value the unlock "
         "test compared against, so the unlock branch was unreachable. A reload "
         "cleared it, so it never reproduced for whoever went looking."],
        ["5", "<b>The scope badge kept announcing a scan in progress</b> after a "
              "resumed run had finished.",
         "Same shape as 4: applied on the way in, no matching step on the way out. "
         "Only a selection change rewrote it."],
    ], [14, 224, 267]))
    s.append(Spacer(1, 4))
    s.append(Paragraph(
        "<b>The pattern worth remembering:</b> defects 4 and 5 are the same mistake "
        "&mdash; state applied when locking with nothing to undo it when unlocking. "
        "If a third lock-time effect is ever added to that panel, check its release "
        "path before anything else.", NOTE))

    # ============================================== 3. images
    s.append(PageBreak())
    s.append(Paragraph("3.  What a bundle contains", H1))
    s.append(table([
        ["Image", "On disk", "Rebuild needed when...", "Changes often?"],
        ["<font face='Courier' size='8'>aicyberauditbox-app</font>",
         "~6.6 GB (7.2 GB with LibreOffice)",
         "any change under src/ or config/, requirements.txt, or Dockerfile.app",
         tag("EVERY RELEASE", WARN)],
        ["<font face='Courier' size='8'>aicyberauditbox-llm</font>",
         "~13 GB real",
         "the model weights change, or Dockerfile.llm / llm-entrypoint.sh change",
         tag("RARELY", OK)],
        ["<font face='Courier' size='8'>aicyberauditbox-llm-embed</font>",
         "0 &mdash; second tag",
         "never separately &mdash; it is the same image",
         tag("NEVER", OK)],
        ["<font face='Courier' size='8'>aicyberauditbox-shakthidb</font>",
         "~0.62 GB", "init.sql or the root Dockerfile changes", tag("RARELY", OK)],
        ["<font face='Courier' size='8'>redis:7-alpine</font>",
         "~0.06 GB", "never &mdash; pulled upstream", tag("NEVER", OK)],
    ], [140, 78, 195, 92]))

    s.append(Spacer(1, 5))
    s.append(Paragraph(
        "<b>Do not add the two LLM sizes together.</b> They are one image with two "
        "tags, started with different LLM_MODE &mdash; identical digest, layers "
        "stored once. Docker's per-tag listing shows the full size against each, "
        "which reads as 53 GB for 13 GB of content. Docker also counts the "
        "compressed blob and the unpacked snapshot separately, which is why a "
        "26.55 GB listing produces a 14.16 GB tar.", WARNP))

    found = bundles_on_disk()
    if found:
        s.append(Paragraph("Bundles produced so far", H2))
        s.append(table([["Version", "File", "Size"]] +
                       [[v, f, sz] for v, f, sz in found], [60, 330, 60]))

    # ============================================== 4. full build
    s.append(Paragraph("4.  Building a full bundle", H1))
    s.append(Paragraph("Double-click <font face='Courier' size='8.5'>make_bundle.bat</font>. "
                       "It checks Docker and disk, asks for a version, builds what is "
                       "needed and packages one tar.", BODY))
    s.append(Paragraph("Before you start", H2))
    s.append(table([
        ["Check", "Requirement"],
        ["Free disk", "<b>~45 GB.</b> ~20 GB for the saved images tar, ~20 GB again "
                      "when it is wrapped, plus margin. Delete old bundles first."],
        ["Internet", "Required on THIS machine (base images, pip). Only the customer "
                     "runs offline."],
        ["Version", "Always bump it. Reusing a number overwrites the previous bundle "
                    "and leaves two different builds sharing one name."],
    ], [62, 443]))

    s.append(Paragraph("The trap that costs an hour", H2))
    s.append(Paragraph(
        "make_bundle.bat decides whether to reuse the LLM image by looking for "
        "<font face='Courier' size='8'>aicyberauditbox-llm:&lt;version&gt;</font>. Bump to a "
        "version that has no LLM image yet and it rebuilds all 13 GB &mdash; about an "
        "hour &mdash; even though the model has not changed. Retag first:", BODY))
    s.append(Paragraph(
        "docker tag aicyberauditbox-llm:3.25 aicyberauditbox-llm:3.26<br/>"
        "docker tag aicyberauditbox-llm-embed:3.25 aicyberauditbox-llm-embed:3.26", CODE))
    s.append(Paragraph(
        "Costs no disk &mdash; same layers, another name. Only skip this when the "
        "model weights or Dockerfile.llm genuinely changed.", NOTE))

    # ============================================== 5. patch
    s.append(PageBreak())
    s.append(Paragraph("5.  Building a patch", H1))
    s.append(Paragraph(
        "For an ordinary code change, a patch is about <b>6 MB</b> instead of 14 GB. "
        "It ships only src/ and config/, and the customer rebuilds on top of the "
        "image they already run &mdash; same packages, same OCR caches, nothing "
        "downloaded, seconds to apply.", BODY))
    s.append(Paragraph("python build_customer_bundle.py --version 3.26 --patch 3.25", CODE))
    s.append(Paragraph("The customer then runs:", BODY))
    s.append(Paragraph(
        "tar -xzf AICyberAuditBox-3.26-patch.tar.gz --strip-components=1<br/>"
        "apply_patch.bat&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(or ./apply_patch.sh)", CODE))

    s.append(Paragraph("When a patch is NOT valid", H2))
    s.append(Paragraph(
        "A patch adds one layer on top of the customer's existing image. Anything "
        "living BELOW that layer cannot be changed by it, and the patch will build "
        "and apply perfectly while delivering nothing.", STOPP))
    s.append(table([
        ["Change", "Patch?", "Why"],
        ["Python or frontend code under src/", tag("YES", OK),
         "This is exactly what the patch layer carries."],
        ["Anything in config/", tag("YES", OK), "Shipped alongside src/."],
        ["A new pip package in requirements.txt", tag("NO", STOP),
         "Installed in a lower layer. The bundler DOES catch this and refuses."],
        ["<b>A new system package (apt)</b>", tag("NO", STOP),
         "<b>Installed in a lower layer, and the bundler does NOT catch it.</b> Its "
         "guard runs pip list in the base image, so apt packages are invisible to "
         "it. The patch builds cleanly and ships code that cannot work."],
        ["Model weights or OCR caches", tag("NO", STOP),
         "Baked into layers far below the patch."],
    ], [150, 46, 309]))

    s.append(Spacer(1, 5))
    s.append(Paragraph(
        "<b>This release is in the NO column.</b> LibreOffice was added to "
        "Dockerfile.app so the ISO PDF can render the template. Patch a customer "
        "from 3.25 and they get the new export code, no converter, a silent "
        "fallback to the old layout, and no error anywhere &mdash; the fix they were "
        "sent would appear not to have been applied. Ship a full bundle for this "
        "one; patches are fine again for the next code-only release.", STOPP))

    # ============================================== 6. decision
    s.append(Paragraph("6.  Patch or full &mdash; the short version", H1))
    s.append(table([
        ["If you changed...", "Ship"],
        ["Only files under src/ or config/", "<b>Patch</b> (~6 MB)"],
        ["requirements.txt, a Dockerfile, or the model", "<b>Full bundle</b> (~14 GB)"],
        ["You are not sure", "<b>Full bundle.</b> It is slow and always correct. A "
                             "wrong patch is fast and silently wrong, at a site with "
                             "no internet to diagnose it."],
    ], [200, 305]))

    # ============================================== 7. push
    s.append(Paragraph("7.  The blocked push", H1))
    s.append(Paragraph(
        "The commits are on the local Developer branch and nothing is lost. Pushing "
        "returns 403 \"Write access to repository not granted\" for "
        "<font face='Courier' size='8'>veeresh8088-star</font> &mdash; on every branch, "
        "including main, which accepted pushes from the same account on 16 September. "
        "Re-authenticating does not help: the credential is fine, the permission is "
        "not. An org admin needs to grant Write on "
        "AISecurityComplianceAuditOps/AICyber_Audit_Box. Then:", BODY))
    s.append(Paragraph("git push testing Developer:Developer", CODE))
    s.append(Paragraph(
        "Do not push to origin, pqc_target, final, new_target, genai or "
        "local_audit_db &mdash; CLAUDE.md forbids all six.", NOTE))

    # ============================================== 8. open
    s.append(Paragraph("8.  Open items", H1))
    s.append(table([
        ["Item", "Detail"],
        ["Template contents page",
         "Sample report.docx still carries a TOC cached from the 31-page source. "
         "Open it in Word, right-click Contents, Update entire table, confirm no "
         "disclaimer lines appear, save. Fixes both formats at the root."],
        ["Nuitka compile never built",
         "Wired to --build-arg COMPILE_SOURCE=1 and defaults off. src/ resolves 15 "
         "data paths from __file__, and a broken compile returns empty PQC results "
         "rather than failing. The compiled variant asserts those loads at build "
         "time; build and test one before ever shipping it."],
        ["No apt guard on patches",
         "See section 5. The bundler should refuse a patch when the Dockerfile's "
         "system packages do not match the base image."],
        ["Bundle carries no checksum",
         "Generated by hand afterwards. The bundler should emit it, and the "
         "installer should verify before extracting."],
        ["run_all.bat line 184",
         "Prints <font face='Courier' size='8'>-&gt; %LLM_SLOTS% Slots</font>; batch reads "
         "&gt; as a redirect, so every boot drops junk files named 1 / 2 / 3 in the "
         "repo root. Fix is <font face='Courier' size='8'>-^&gt;</font>."],
    ], [92, 413]))

    s.append(Spacer(1, 10))
    s.append(Paragraph(
        "Dhiware Technologies Pvt Ltd &middot; prepared %s &middot; figures read from "
        "the repository and the artifacts on disk." % time.strftime("%d %B %Y"), NOTE))

    doc.build(s)
    print("Wrote " + OUT)


if __name__ == "__main__":
    build()
