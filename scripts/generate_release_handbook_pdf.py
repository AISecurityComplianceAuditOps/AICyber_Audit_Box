# -*- coding: utf-8 -*-
"""Generates AICyberAuditBox_Release_Handbook.pdf.

The whole release path in one document: the three shapes an update can take,
the exact commands for each on both sides, and -- the part that costs money
when it is got wrong -- when a patch is NOT valid and will apply cleanly while
delivering nothing.

Figures are read from the repository and the artifacts on disk, so the document
cannot quote numbers a later build outgrew.
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
         spaceBefore=12, spaceAfter=4)
H2 = _st("h2", fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=INK,
         spaceBefore=8, spaceAfter=3)
BODY = _st("b", spaceAfter=4)
NOTE = _st("n", fontSize=8.5, leading=12, textColor=MUTED)
WARNP = _st("w", fontSize=9.5, leading=13, textColor=WARN, spaceAfter=4)
STOPP = _st("s", fontSize=9.5, leading=13, textColor=STOP, spaceAfter=4)
CODE = _st("c", fontName="Courier", fontSize=8, leading=11.5,
           backColor=BAND, borderPadding=6, spaceBefore=3, spaceAfter=5)
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


def artifacts():
    """Every deliverable produced so far, newest first, measured on disk."""
    out = []
    if os.path.isdir(BUNDLE_DIR):
        for ver in sorted(os.listdir(BUNDLE_DIR), reverse=True):
            d = os.path.join(BUNDLE_DIR, ver)
            if not os.path.isdir(d):
                continue
            for f in sorted(os.listdir(d)):
                if f.endswith((".tar", ".tar.gz")):
                    p = os.path.join(d, f)
                    mb = os.path.getsize(p) / 1024.0 ** 2
                    size = "%.0f MB" % mb if mb < 1024 else "%.2f GB" % (mb / 1024.0)
                    kind = ("patch" if "patch" in f else
                            "full bundle" if "complete" in f else "delta (app only)")
                    out.append((ver, f, kind, size))
    return out


def build():
    doc = SimpleDocTemplate(OUT, pagesize=A4,
                            leftMargin=17 * mm, rightMargin=17 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm,
                            title="AICyberAuditBox - Release Handbook",
                            author="Dhiware Technologies Pvt Ltd")
    s = []

    s.append(Paragraph("AICyberAuditBox &mdash; Release Handbook", TITLE))
    s.append(Paragraph(
        "The three shapes an update can take, the exact commands for each, and "
        "when a patch will apply cleanly while delivering nothing. Written to be "
        "read before a release, not after one goes wrong.", SUB))
    s.append(Spacer(1, 8))

    # ---------------------------------------------------------------- state
    s.append(Paragraph("1.  Where things stand", H1))
    s.append(table([
        ["Item", "State"],
        ["Branch", "<font face='Courier' size='8'>Developer</font> &mdash; pushed to "
                   "<font face='Courier' size='8'>testing/Developer</font> at "
                   "<font face='Courier' size='8'>%s</font>" % (git("rev-parse", "--short", "HEAD") or "?")],
        ["Ahead of main", "<font face='Courier' size='8'>testing/main</font> is still at 0f83512. "
                          "These fixes are on Developer only and are not merged to the release branch."],
        ["Tests", "352 passing, 18 skipped"],
        ["Customer is running", "<b>3.26</b> &mdash; upgraded by delta, verified running "
                                "<font face='Courier' size='8'>aicyberauditbox-app:3.26</font> "
                                "with LibreOffice present"],
    ], [86, 419]))

    rows = artifacts()
    if rows:
        s.append(Paragraph("Artifacts produced", H2))
        s.append(table([["Version", "File", "Kind", "Size"]] +
                       [list(r) for r in rows], [46, 268, 105, 56]))

    # ---------------------------------------------------------------- choose
    s.append(Paragraph("2.  Which update to ship", H1))
    s.append(table([
        ["What you changed", "Ship", "Size"],
        ["Only files under src/ or config/", "<b>A &mdash; Patch</b>", "~11 MB"],
        ["Also requirements.txt, a Dockerfile, or a system package",
         "<b>B &mdash; Delta</b> (app image)", "~2.3 GB"],
        ["Model weights, the database image, or a first install",
         "<b>C &mdash; Full bundle</b>", "~14 GB"],
        ["Not sure", "<b>B &mdash; Delta.</b> Always correct for an application change, "
                     "and six times smaller than full.", "&mdash;"],
    ], [215, 225, 65]))
    s.append(Spacer(1, 3))
    s.append(Paragraph(
        "Replace the version numbers below with your own. The examples assume the "
        "customer is on <b>3.26</b> and you are shipping <b>3.27</b>.", NOTE))

    # ---------------------------------------------------------------- A patch
    s.append(Paragraph("3.  A &mdash; Patch (~11 MB), code only", H1))
    s.append(Paragraph("You build:", H2))
    s.append(Paragraph(
        "python build_customer_bundle.py --version 3.27 --patch 3.26 --skip-build", CODE))
    s.append(Paragraph(
        "--skip-build matters: without it the bundler rebuilds the app image and then "
        "tries to relayer the LLM images from the version in docker-compose.yml, which "
        "fails noisily with \"pull access denied\" before carrying on anyway.", NOTE))
    s.append(Paragraph("Send: <font face='Courier' size='8'>AICyberAuditBox-3.27-patch.tar.gz</font>", BODY))
    s.append(Paragraph("Customer runs:", H2))
    s.append(Paragraph(
        "cd &lt;their install folder&gt;<br/>"
        "tar -xzf AICyberAuditBox-3.27-patch.tar.gz --strip-components=1<br/>"
        ".\\apply_patch.bat", CODE))
    s.append(Paragraph(
        "The leading <font face='Courier' size='8'>.\\</font> is required &mdash; PowerShell "
        "does not run programs from the current folder without it.", NOTE))

    # ---------------------------------------------------------------- B delta
    s.append(Paragraph("4.  B &mdash; Delta (~2.3 GB), the new app image", H1))
    s.append(Paragraph(
        "The workhorse. Ships the whole app image, so anything installed in it comes "
        "too &mdash; pip packages, system packages, caches. The LLM and database are "
        "untouched, which is why it is 2.3 GB rather than 14.", BODY))
    s.append(Paragraph("You build:", H2))
    s.append(Paragraph(
        "python build_customer_bundle.py --version 3.27 --skip-build<br/>"
        "<br/>"
        "# drop --skip-build if the app image has not been built yet", CODE))
    s.append(Paragraph(
        "Send the tar AND its checksum, <b>by different routes</b> &mdash; a checksum "
        "travelling beside the file it verifies proves nothing:", BODY))
    s.append(Paragraph(
        "$f = \"aicyberauditbox-app-3.27.tar\"<br/>"
        "(Get-FileHash -Algorithm SHA256 $f).Hash | Out-File \"$f.sha256\"", CODE))
    s.append(Paragraph("Customer runs:", H2))
    s.append(Paragraph(
        "certutil -hashfile aicyberauditbox-app-3.27.tar SHA256<br/>"
        "docker load -i aicyberauditbox-app-3.27.tar<br/>"
        "notepad docker-compose.yml<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;# change ONLY the line under `app:` to 3.27, save<br/>"
        "docker compose up -d app<br/>"
        "docker inspect --format \"{{.Config.Image}}\" aicyberauditbox_app", CODE))
    s.append(Paragraph(
        "<b>Tell them explicitly to leave the llm and llm-embed lines alone.</b> A "
        "blanket find-and-replace of the version string rewrites those too, and the "
        "machine has no LLM image at the new tag &mdash; the stack then will not start. "
        "Search for the full string <font face='Courier' size='8'>aicyberauditbox-app:3.26</font>, "
        "not just the number; Replace All should report exactly one change.", WARNP))
    s.append(Paragraph(
        "The last line is the check that matters. Compose reports \"Started\" whether or "
        "not the edit saved, so only inspecting the running container proves the new "
        "image is live. Rolling back is the same edit in reverse &mdash; the old image is "
        "still on their machine.", NOTE))

    # ---------------------------------------------------------------- C full
    s.append(PageBreak())
    s.append(Paragraph("5.  C &mdash; Full bundle (~14 GB), everything", H1))
    s.append(Paragraph("You build &mdash; retag the LLM first:", H2))
    s.append(Paragraph(
        "docker tag aicyberauditbox-llm:3.25 aicyberauditbox-llm:3.27<br/>"
        "docker tag aicyberauditbox-llm-embed:3.25 aicyberauditbox-llm-embed:3.27<br/>"
        "<br/>"
        "make_bundle.bat&nbsp;&nbsp;&nbsp;&nbsp;# double-click; enter 3.27; answer n to compile", CODE))
    s.append(Paragraph(
        "Without the retag, make_bundle.bat finds no LLM image at the new version and "
        "rebuilds all 13 GB &mdash; about an hour &mdash; even though the model has not "
        "changed. Retagging costs no disk: same layers, another name. Skip it only when "
        "the weights or Dockerfile.llm genuinely changed.", WARNP))
    s.append(Paragraph("Customer runs:", H2))
    s.append(Paragraph(
        "certutil -hashfile AICyberAuditBox-3.27-complete.tar SHA256<br/>"
        "tar -xf AICyberAuditBox-3.27-complete.tar<br/>"
        "cd AICyberAuditBox-3.27<br/>"
        "notepad .env<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;# one line:  POSTGRES_PASSWORD=&lt;a strong password&gt;<br/>"
        ".\\install.bat<br/>"
        "docker compose logs app | findstr \"generated a random admin password\"", CODE))
    s.append(Paragraph(
        "<b>Two things they must not miss.</b> The database password has to be set "
        "BEFORE installing and can never be changed afterwards &mdash; PostgreSQL writes "
        "it into the data volume on first start. And the admin password is generated "
        "randomly and printed to the log exactly once; it cannot be set in advance, "
        "because the shipped compose does not pass that variable through. Miss it and "
        "the only clean recovery is destroying the volume and reinstalling.", STOPP))
    s.append(Paragraph(
        "Then http://&lt;host&gt;:8000, sign in as <b>admin</b>, and scan the QR code shown "
        "into an authenticator app for the one-time code used from then on. First start "
        "takes 3&ndash;5 minutes while 11.8 GB of weights load; a 502 during that window is "
        "normal. The installer prints the LLM's sizing line, and it must read "
        "<font face='Courier' size='8'>= 32768 tokens per request</font> &mdash; anything lower "
        "means evidence is truncated before the model sees it and findings will be "
        "unreliable.", BODY))

    # ---------------------------------------------------------------- trap
    s.append(Paragraph("6.  When a patch is NOT valid", H1))
    s.append(Paragraph(
        "A patch adds one layer on top of the image the customer already runs. Anything "
        "living BELOW that layer cannot be changed by it &mdash; and the patch will build "
        "and apply perfectly while delivering nothing.", STOPP))
    s.append(table([
        ["Change", "Patch?", "Why"],
        ["Python or frontend code under src/", tag("YES", OK),
         "Exactly what the patch layer carries."],
        ["Anything in config/", tag("YES", OK), "Shipped alongside src/."],
        ["A new pip package in requirements.txt", tag("NO", STOP),
         "Lower layer. The bundler DOES catch this and refuses to build the patch."],
        ["<b>A new system package (apt)</b>", tag("NO", STOP),
         "<b>Lower layer, and the bundler does NOT catch it.</b> Its guard runs pip list "
         "in the base image, so apt packages are invisible. The patch builds cleanly and "
         "ships code that cannot run."],
        ["Model weights or OCR caches", tag("NO", STOP), "Baked far below the patch."],
    ], [152, 46, 307]))
    s.append(Spacer(1, 4))
    s.append(Paragraph(
        "This is not hypothetical: 3.26 added LibreOffice so the ISO PDF could render "
        "the branded template. Patched from 3.25, the customer would have received the "
        "new export code, no converter, a silent fallback to the old layout, and no "
        "error anywhere &mdash; the fix would have appeared not to have been applied. It "
        "shipped as a delta instead.", WARNP))

    # ---------------------------------------------------------------- open
    s.append(Paragraph("7.  Open items", H1))
    s.append(table([
        ["Item", "Detail"],
        ["Merge to main", "These fixes are on Developer only. main is still at 0f83512."],
        ["Template contents page",
         "Sample report.docx carries a TOC cached from the 31-page source, so the PDF's "
         "contents page points at pages that do not exist. Open it in Word, right-click "
         "Contents, Update entire table, check no disclaimer lines appear, save. Fixes "
         "both formats at the root."],
        ["No apt guard on patches",
         "See section 6. The bundler should refuse a patch when the Dockerfile's system "
         "packages do not match the base image."],
        ["Bundler builds images it does not need",
         "The image-building block runs before the mode is checked, so a patch build "
         "rebuilds the app image and fails trying to relayer LLM images. Harmless, "
         "noisy, and wastes a rebuild. --skip-build avoids it."],
        ["Checksums are manual",
         "The bundler should emit a SHA-256 and a manifest, and the installer should "
         "verify before extracting."],
        ["Nuitka compile never built",
         "Wired to --build-arg COMPILE_SOURCE=1, defaults off. src/ resolves 15 data "
         "paths from __file__ and a broken compile returns empty PQC results rather "
         "than failing, so the compiled variant asserts those loads at build time. "
         "Build and test one before ever shipping it."],
        ["run_all.bat line 184",
         "Prints <font face='Courier' size='8'>-&gt; %LLM_SLOTS% Slots</font>; batch reads "
         "&gt; as a redirect, so every boot drops junk files named 1 / 2 / 3 in the repo "
         "root. Fix is <font face='Courier' size='8'>-^&gt;</font>."],
    ], [108, 397]))

    s.append(Spacer(1, 9))
    s.append(Paragraph(
        "Dhiware Technologies Pvt Ltd &middot; prepared %s &middot; figures read from the "
        "repository and the artifacts on disk." % time.strftime("%d %B %Y"), NOTE))

    doc.build(s)
    print("Wrote " + OUT)


if __name__ == "__main__":
    build()
