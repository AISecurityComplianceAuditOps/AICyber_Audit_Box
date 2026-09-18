# -*- coding: utf-8 -*-
"""Generates AICyberAuditBox_Bundling_Plan.pdf -- the step-by-step account of
how a customer bundle is produced, for review before a build is started.

Written to be read by someone deciding whether to approve the build, so it
leads with what the customer receives and what it costs to produce, and states
the open blockers rather than burying them.
"""
import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                               Table, TableStyle)

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "AICyberAuditBox_Bundling_Plan.pdf")

INK = colors.HexColor("#1a1a1a")
MUTED = colors.HexColor("#5b6472")
RULE = colors.HexColor("#d4d9e0")
BAND = colors.HexColor("#f2f4f7")
ACCENT = colors.HexColor("#1f4e79")
WARN = colors.HexColor("#8a4b08")

_ss = getSampleStyleSheet()


def _st(name, **kw):
    base = dict(fontName="Helvetica", fontSize=9.5, leading=14, textColor=INK,
                alignment=TA_LEFT)
    base.update(kw)
    return ParagraphStyle(name, parent=_ss["Normal"], **base)


TITLE = _st("t", fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=ACCENT)
SUB = _st("sub", fontSize=10, leading=14, textColor=MUTED)
H1 = _st("h1", fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=ACCENT,
         spaceBefore=14, spaceAfter=5)
H2 = _st("h2", fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=INK,
         spaceBefore=9, spaceAfter=3)
BODY = _st("b", spaceAfter=5)
NOTE = _st("n", fontSize=9, leading=13, textColor=MUTED)
WARNP = _st("w", fontSize=9.5, leading=13.5, textColor=WARN)
CODE = _st("c", fontName="Courier", fontSize=8.5, leading=12,
           backColor=BAND, borderPadding=5, spaceBefore=3, spaceAfter=6)


def bullets(items, style=BODY):
    out = []
    for it in items:
        out.append(Paragraph("&bull;&nbsp;&nbsp;" + it, style))
    return out


CELL = _st("cell", fontSize=8.5, leading=11.5)
CELLB = _st("cellb", fontName="Helvetica-Bold", fontSize=8.5, leading=11.5)


def table(rows, widths, header=True, align_right=()):
    # Every cell becomes a Paragraph. A bare string in a reportlab table does
    # not wrap -- it runs straight through the right-hand border and off the
    # page, which is what the first draft of this document did.
    wrapped = []
    for r, row in enumerate(rows):
        out = []
        for cell in row:
            if isinstance(cell, str):
                out.append(Paragraph(cell, CELLB if (header and r == 0) else CELL))
            else:
                out.append(cell)
        wrapped.append(out)
    t = Table(wrapped, colWidths=widths, hAlign="LEFT")
    cmds = [
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        cmds += [("BACKGROUND", (0, 0), (-1, 0), BAND),
                 ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
    for col in align_right:
        cmds.append(("ALIGN", (col, 0), (col, -1), "RIGHT"))
    t.setStyle(TableStyle(cmds))
    return t


def build():
    doc = SimpleDocTemplate(OUT, pagesize=A4,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title="AICyberAuditBox - Customer Bundling Plan",
                            author="AICyberAuditBox")
    s = []

    s.append(Paragraph("AICyberAuditBox &mdash; Customer Bundling Plan", TITLE))
    s.append(Paragraph(
        "How one air-gapped customer bundle is produced, step by step. "
        "Read this before starting a build: the build takes hours and about "
        "60&nbsp;GB of disk, and two decisions baked into it cannot be changed "
        "afterwards without rebuilding.", SUB))
    s.append(Spacer(1, 10))

    # ---------------------------------------------------------------- outcome
    s.append(Paragraph("1.  What the customer receives", H1))
    s.append(Paragraph(
        "A single <b>.tar</b> file. They copy it onto an air-gapped server, "
        "extract it, and run one installer. Nothing is downloaded, nothing is "
        "installed first. The only prerequisite on their machine is Docker.", BODY))
    s.append(Paragraph(
        "Everything the product needs at runtime is inside that tar: the model "
        "weights, the OCR and reranker caches, PostgreSQL, Redis, the API and "
        "the frontend. There is no pip index, no Hugging Face call, no registry "
        "pull at any point after handover.", BODY))
    s.append(Spacer(1, 4))
    s.append(Paragraph("Their entire installation:", H2))
    s.append(Paragraph(
        "tar -xf AICyberAuditBox-&lt;version&gt;-complete.tar<br/>"
        "cd AICyberAuditBox-&lt;version&gt;<br/>"
        "./install.sh&nbsp;&nbsp;&nbsp;&nbsp;(or install.bat on Windows)", CODE))

    # ------------------------------------------------------------- what's in
    s.append(Paragraph("2.  What goes inside the tar", H1))
    s.append(table([
        ["Component", "Image tag", "Approx. size", "Why it is there"],
        ["Application", "aicyberauditbox-app:&lt;ver&gt;", "6.6 GB",
         "FastAPI + frontend, Python deps, doctr OCR and reranker caches baked in "
         "so the container never reaches Hugging Face"],
        ["LLM (completion)", "aicyberauditbox-llm:&lt;ver&gt;", "12.7 GB",
         "llama.cpp server with the Gemma 4 12B Q8_0 weights baked in"],
        ["LLM (embedding)", "aicyberauditbox-llm-embed:&lt;ver&gt;", "shared",
         "Same image, second tag. The entrypoint picks the role from LLM_MODE, "
         "so the layers are shared and cost nothing extra"],
        ["Database", "aicyberauditbox-shakthidb:3.10", "0.6 GB",
         "pgvector/Postgres with init.sql applied on first start"],
        ["Cache", "redis:7-alpine", "0.06 GB", "Live telemetry / metrics"],
        ["Compose + installers", "(files)", "under 1 MB",
         "docker-compose.yml with image tags pinned to this bundle, install.sh, "
         "install.bat, INSTALL_v&lt;ver&gt;.md"],
    ], [62, 116, 48, 264]))
    s.append(Spacer(1, 4))
    s.append(Paragraph(
        "Total: roughly <b>20 GB</b> of images in one tar. The compose file shipped "
        "is deliberately <i>not</i> the repo's own &mdash; the repo copy carries "
        "<font face='Courier' size='8'>build:</font> directives pointing at "
        "Dockerfiles the customer does not have.", NOTE))

    # -------------------------------------------------------------- the steps
    s.append(PageBreak())
    s.append(Paragraph("3.  The build, step by step", H1))
    s.append(Paragraph(
        "You double-click <font face='Courier' size='8.5'>make_bundle.bat</font> "
        "in the repo root. It runs these in order and stops at the first failure.", BODY))

    steps = [
        ("0", "Pre-flight",
         "Confirms Docker is running, then checks free disk. A full bundle needs "
         "about 60 GB: ~20 GB of images in Docker's store, the same again when "
         "<font face='Courier' size='8'>docker save</font> writes them to a tar, "
         "and the outer wrap on top. This check exists so the build refuses in "
         "five seconds instead of failing three hours in with a full disk."),
        ("1", "Ask for the version",
         "Defaults to whatever docker-compose.yml currently names. The tag has to "
         "match what the shipped compose file references &mdash; guess it wrong and "
         "the customer gets a compose pointing at an image the bundle does not "
         "contain, with no registry to fall back on."),
        ("2", "Ask whether to compile the source",
         "Nuitka compiles src/ into a binary so the customer cannot read your "
         "Python. <b>Defaults to off.</b> See section 5 for why."),
        ("3", "Build the four images",
         "ShaktiDB (Postgres), Redis (pulled), the LLM image, then the app image. "
         "Any image already present at that exact tag is reused rather than "
         "rebuilt. The LLM step copies ~12.6 GB of weights into the build context "
         "and looks idle while it does &mdash; this is the slow one."),
        ("4", "Package",
         "Hands off to <font face='Courier' size='8'>build_customer_bundle.py "
         "--full --skip-build</font>, which runs one "
         "<font face='Courier' size='8'>docker save</font> across all five tags, "
         "verifies every tag actually landed in the tar by reading its manifest, "
         "stamps the version and real measured size into the compose file, both "
         "installers and the install guide, then wraps the lot into one tar."),
        ("5", "Hand over",
         "One file in ../customer_deployment_package/v&lt;version&gt;/."),
    ]
    rows = [["#", "Stage", "What happens"]]
    for n, name, what in steps:
        rows.append([n, "<b>" + name + "</b>", what])
    s.append(table(rows, [18, 82, 390]))

    s.append(Spacer(1, 6))
    s.append(Paragraph(
        "<b>Why --skip-build is passed.</b> Every image is built in step 3, with "
        "the compile choice from step 2 applied. Letting the packaging script "
        "build as well would rebuild the app image without that argument, and a "
        "run that asked for compiled source would silently ship readable source.",
        NOTE))

    # ------------------------------------------------------------- decisions
    s.append(Paragraph("4.  Decisions baked into this bundle", H1))
    s.append(Paragraph("Only the 12B model ships", H2))
    s.append(Paragraph(
        "The image previously carried a second completion model, Gemma 4 E4B "
        "(5.4 GB), as a fallback for a machine too small to hold the 12B. It has "
        "been removed: this bundle targets a site sized for the 12B, and 5.4 GB "
        "is a real cost in every handover.", BODY))
    s.append(Paragraph(
        "<b>The consequence, stated plainly:</b> the 12B needs 12.5 GB resident "
        "before a single request slot. If the customer's Docker VM cannot give "
        "the container that &mdash; common on a 32 GB Windows or macOS host, where "
        "the VM often exposes only ~16 GB &mdash; there is now no smaller model in "
        "the image to fall back to, and no internet to fetch one. Confirm the "
        "target machine's <i>Docker</i> memory allowance, not its host RAM, "
        "before shipping.", WARNP))
    s.append(Paragraph(
        "Three places that used to recommend LLM_MODEL=e4b were corrected so they "
        "no longer point at a model that is not there: the entrypoint's model "
        "selection, its out-of-memory message, and the customer compose comments. "
        "An operator can still mount other weights and name them by absolute path.",
        NOTE))

    # --------------------------------------------------------------- nuitka
    s.append(Paragraph("5.  Source protection (Nuitka) &mdash; off by default", H1))
    s.append(Paragraph(
        "Nuitka compiles the whole of src/ into a single binary, so the shipped "
        "image contains no readable .py. It is wired up and selectable, but "
        "defaults to <b>off</b> for a specific reason.", BODY))
    s.append(Paragraph(
        "src/ resolves <b>15 data paths from <font face='Courier' size='8.5'>"
        "__file__</font></b> &mdash; the PQC knowledge JSON files, the ISO report "
        "assets, the embeddings cache. Compiling the package into one .so moves "
        "<font face='Courier' size='8.5'>__file__</font> out from under every one "
        "of them. The worst of these is "
        "<font face='Courier' size='8.5'>pqc_crypto_db._load_json</font>, which "
        "catches the failure and returns an empty dict:", BODY))
    s.append(Paragraph(
        'except Exception as exc:<br/>'
        '&nbsp;&nbsp;&nbsp;&nbsp;print(f"[pqc_crypto_db] WARNING: Could not load ...")<br/>'
        '&nbsp;&nbsp;&nbsp;&nbsp;return {}', CODE))
    s.append(Paragraph(
        "So a broken compile does not crash. It produces a product that starts "
        "cleanly, runs audits, and returns empty PQC results &mdash; at a customer "
        "site, with no internet and no source to inspect. That is the failure mode "
        "worth engineering against.", WARNP))
    s.append(Paragraph(
        "The compiled image therefore verifies those loads <i>at build time</i> and "
        "fails the build if they come back empty. Turn it on only after one "
        "compiled build has been produced and tested end to end.", BODY))

    # -------------------------------------------------------------- blockers
    s.append(Paragraph("6.  Before you start &mdash; open blockers", H1))
    s.append(table([
        ["", "Blocker", "What it means"],
        ["1", "Disk space",
         "This machine has ~17 GB free on C:. A full bundle needs ~60 GB. Either "
         "free space (the stale aicyberauditbox-llm:2.2 and llm-embed:2.2 images "
         "hold 12.5 GB, and dist/ holds ~6 GB of a stale PyInstaller build), or "
         "build to another drive with --out."],
        ["2", "No images at the required versions",
         "docker-compose.yml names app:3.22, llm:3.22, llm-embed:3.22, "
         "shakthidb:3.10. This machine has app:3.9, llm:2.2, llm-embed:2.2, "
         "shakthidb:2.1. Only redis matches, so all four are built from scratch "
         "on the first run &mdash; that is the multi-hour part."],
        ["3", "The build machine needs internet",
         "Dockerfile.llm pulls ghcr.io/ggml-org/llama.cpp:server and the DB image "
         "pulls pgvector/pgvector:pg16. Only the <i>customer</i> runs offline; "
         "this machine must be online while building."],
        ["4", "Licence signing key is lost",
         "Per CLAUDE.md: config/licence_public.pem has no private half anywhere, "
         "so no licence can be issued that the shipped key will verify. No "
         "customer bundle carries that public key yet, so rotating is still free "
         "&mdash; but it must be done before a bundle that includes it ships."],
    ], [18, 116, 356]))

    s.append(Spacer(1, 8))
    s.append(Paragraph("7.  What I will run", H1))
    s.append(Paragraph("make_bundle.bat", CODE))
    s.append(Paragraph(
        "That is the whole operator-facing surface. Everything above happens "
        "inside it. The equivalent by hand, if you ever need to drive it "
        "manually:", BODY))
    s.append(Paragraph(
        "docker build -f Dockerfile     -t aicyberauditbox-shakthidb:3.10 .<br/>"
        "docker pull  redis:7-alpine<br/>"
        "docker build -f Dockerfile.llm -t aicyberauditbox-llm:&lt;ver&gt; .<br/>"
        "docker tag   aicyberauditbox-llm:&lt;ver&gt; aicyberauditbox-llm-embed:&lt;ver&gt;<br/>"
        "docker build -f Dockerfile.app --build-arg COMPILE_SOURCE=0 \\<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
        "-t aicyberauditbox-app:&lt;ver&gt; .<br/>"
        "python build_customer_bundle.py --version &lt;ver&gt; --full --skip-build",
        CODE))

    s.append(Spacer(1, 10))
    s.append(Paragraph(
        "Generated for review before the first build. Sizes are measured from this "
        "machine's current images; the install guide shipped to the customer is "
        "stamped with the size of the tar actually produced, so the two cannot "
        "drift.", NOTE))

    doc.build(s)
    print("Wrote " + OUT)


if __name__ == "__main__":
    build()
