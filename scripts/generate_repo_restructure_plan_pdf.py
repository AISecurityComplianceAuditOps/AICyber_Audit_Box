# -*- coding: utf-8 -*-
"""Generates AICyberAuditBox_Repository_Restructure_Plan.pdf.

A gap analysis of the current AICyber_Audit_Box repository against the target
release-engineering structure (Source / TPS / Tools / Target, the Design +
Official + Operational documentation tree, a four-tier branch model, versioned
bundles with checksums, pipeline, signing, backup and automation), plus the
order in which to adopt it.

Plan only. Nothing in the repository is modified by this script.
"""
import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "AICyberAuditBox_Repository_Restructure_Plan.pdf")

INK = colors.HexColor("#1a1a1a")
MUTED = colors.HexColor("#5b6472")
RULE = colors.HexColor("#d4d9e0")
BAND = colors.HexColor("#f2f4f7")
ACCENT = colors.HexColor("#1f4e79")
WARN = colors.HexColor("#8a4b08")
OK = colors.HexColor("#1d6b3f")
GAP = colors.HexColor("#9b2226")

_ss = getSampleStyleSheet()


def _st(name, **kw):
    base = dict(fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK,
                alignment=TA_LEFT)
    base.update(kw)
    return ParagraphStyle(name, parent=_ss["Normal"], **base)


TITLE = _st("t", fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=ACCENT)
SUB = _st("sub", fontSize=9.5, leading=13.5, textColor=MUTED)
H1 = _st("h1", fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=ACCENT,
         spaceBefore=13, spaceAfter=4)
H2 = _st("h2", fontName="Helvetica-Bold", fontSize=10, leading=13.5, textColor=INK,
         spaceBefore=8, spaceAfter=3)
BODY = _st("b", spaceAfter=4)
NOTE = _st("n", fontSize=8.5, leading=12, textColor=MUTED)
WARNP = _st("w", fontSize=9, leading=12.5, textColor=WARN)
CODE = _st("c", fontName="Courier", fontSize=8, leading=11,
           backColor=BAND, borderPadding=5, spaceBefore=3, spaceAfter=5)
CELL = _st("cell", fontSize=8, leading=10.8)
CELLB = _st("cellb", fontName="Helvetica-Bold", fontSize=8, leading=10.8)
TREE = _st("tree", fontName="Courier", fontSize=7.8, leading=10.2)


def table(rows, widths, header=True):
    wrapped = []
    for r, row in enumerate(rows):
        out = []
        for cell in row:
            if isinstance(cell, str):
                out.append(Paragraph(cell, CELLB if (header and r == 0) else CELL))
            else:
                out.append(cell)
        wrapped.append(out)
    t = Table(wrapped, colWidths=widths, hAlign="LEFT", repeatRows=1 if header else 0)
    cmds = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]
    if header:
        cmds += [("BACKGROUND", (0, 0), (-1, 0), BAND)]
    t.setStyle(TableStyle(cmds))
    return t


def tag(text, colour):
    return Paragraph('<font color="%s"><b>%s</b></font>' % (colour.hexval(), text), CELL)


HAVE = lambda: tag("HAVE", OK)
PART = lambda: tag("PARTIAL", WARN)
NONE = lambda: tag("MISSING", GAP)


def build():
    doc = SimpleDocTemplate(OUT, pagesize=A4,
                            leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm,
                            title="AICyberAuditBox - Repository Restructure Plan",
                            author="AICyberAuditBox")
    s = []
    W = 178 * mm / mm * 2.834  # usable width in points, approx 505

    s.append(Paragraph("AICyberAuditBox &mdash; Repository Restructure Plan", TITLE))
    s.append(Paragraph(
        "Gap analysis of <b>AISecurityComplianceAuditOps/AICyber_Audit_Box</b> against the "
        "target release-engineering structure, and the order in which to adopt it. "
        "<b>This is a plan only &mdash; nothing in the repository has been changed.</b>", SUB))
    s.append(Spacer(1, 8))

    # ==================================================== 1. where you are
    s.append(Paragraph("1.  Where the repository is today", H1))
    s.append(table([
        ["Area", "Current reality"],
        ["Branches",
         "Four on the remote: <font face='Courier' size='7.5'>main</font>, "
         "<font face='Courier' size='7.5'>Developer</font>, "
         "<font face='Courier' size='7.5'>mcp-integration-v2</font>, and one Semgrep "
         "auto-fix branch. No QC-Staging, no Production."],
        ["Tags", "One: <font face='Courier' size='7.5'>v3.24</font>. Releases are "
                 "otherwise unmarked, so 'what shipped' cannot be answered from git."],
        ["Source", "<font face='Courier' size='7.5'>src/</font> &mdash; 93 files in "
                   "ai / api / core / db. Coherent and already close to the target's "
                   "Application + Common split."],
        ["Root directory",
         "~78 tracked entries. Includes 8 QUICKSTART_v*.md, 7 UPDATE_v*.md, 4 "
         "CUSTOMER_SETUP_GUIDE_v*.md, 2 INSTALL_v*.md, 7 Dockerfiles and 10 run/install "
         "scripts &mdash; version-suffixed documents accumulating at the top level."],
        ["Documentation", "<font face='Courier' size='7.5'>docs/</font> holds 7 files "
                          "(2 HTML guides, 5 PQC PDFs). Most other documents sit loose "
                          "at the root as dated PDFs."],
        ["Pipeline", "Six workflows: ci, security-scan, deploy, e2e, ai-eval, load-test. "
                     "<b>Four of the six are <font face='Courier' size='7.5'>workflow_dispatch</font> "
                     "only</b> &mdash; they run when somebody remembers to press the button."],
        ["Tests", "37 in <font face='Courier' size='7.5'>tests/</font>, 28 in "
                  "<font face='Courier' size='7.5'>qa/</font> (checkpointing, Playwright e2e). "
                  "Good coverage, no published report artefact."],
        ["Supply chain", "No SBOM of this product. No image signing. Trivy and Semgrep "
                         "run and upload SARIF; Dependabot is on."],
    ], [66, 439]))

    s.append(Spacer(1, 5))
    s.append(Paragraph(
        "<b>The honest summary:</b> the engineering is in good shape and the "
        "<i>artefacts of governance</i> are what is missing. Nothing below is about "
        "rewriting code &mdash; it is about making the repository state what it already "
        "does, in a form an auditor or a customer's security team can accept.", BODY))

    # ==================================================== 2. source structure
    s.append(Paragraph("2.  Source structure &mdash; target vs. today", H1))
    s.append(table([
        ["Target", "Status", "What fills it / what to do"],
        ["Source / Configurations_Property", PART(),
         "Have <font face='Courier' size='7.5'>config/</font> (2 files), "
         "<font face='Courier' size='7.5'>.env.example</font>, "
         "<font face='Courier' size='7.5'>sql.config</font>, "
         "<font face='Courier' size='7.5'>pytest.ini</font>. Consolidate the loose root "
         "config files under one tree."],
        ["Source / Common", HAVE(),
         "<font face='Courier' size='7.5'>src/core/</font> is already this: auth, settings, "
         "pii_redactor, text_validation, port_pool, resource_guard, token_tracker."],
        ["Source / Application", HAVE(),
         "<font face='Courier' size='7.5'>src/api/</font>, "
         "<font face='Courier' size='7.5'>src/ai/</font>, "
         "<font face='Courier' size='7.5'>src/db/</font>, "
         "<font face='Courier' size='7.5'>src/core/parsers/</font>."],
        ["Source / Reference_Dependencies", HAVE(),
         "<font face='Courier' size='7.5'>requirements.txt</font> + "
         "<font face='Courier' size='7.5'>requirements.lock.txt</font>. The lock file is "
         "the one that matters for reproducibility; keep both."],
        ["TPS / Open_Source", NONE(),
         "Not tracked anywhere as a register. In use: llama.cpp (GHCR base image), "
         "pgvector/Postgres, Redis, doctr, sentence-transformers, torch, and the "
         "<b>Gemma model weights</b>. The Gemma licence terms in particular should be "
         "recorded here &mdash; the weights ship to customers."],
        ["TPS / Commercials", NONE(),
         "None identified. State that explicitly rather than leaving the folder empty; "
         "'no commercial third-party software' is itself an audit answer."],
        ["Tools / Scripts", HAVE(),
         "<font face='Courier' size='7.5'>scripts/</font> (41), "
         "<font face='Courier' size='7.5'>tools/</font>, and the root run_*/install_* "
         "scripts. Split home-grown from third-party as the target asks."],
        ["Tools / Direct_Bundling_Content", HAVE(),
         "<font face='Courier' size='7.5'>build_customer_bundle.py</font>, "
         "<font face='Courier' size='7.5'>make_bundle.bat</font>, the 7 Dockerfiles, "
         "the 3 compose files, <font face='Courier' size='7.5'>docker/</font>."],
        ["Tools / Product_Application_Docs", PART(),
         "Exists but scattered &mdash; see section 3."],
        ["Target / Binaries, Libraries", PART(),
         "<font face='Courier' size='7.5'>dist/</font> and "
         "<font face='Courier' size='7.5'>build/</font> exist as build output but are not "
         "a declared, gitignored Target tree. Formalise: generated, never committed."],
    ], [116, 52, 337]))

    # ==================================================== 3. docs
    s.append(PageBreak())
    s.append(Paragraph("3.  Documentation structure &mdash; the largest gap", H1))
    s.append(Paragraph(
        "This is where most of the work is. Of the 17 target documents, 3 exist properly, "
        "5 exist informally, and 9 do not exist.", BODY))

    s.append(Paragraph("Design", H2))
    s.append(table([
        ["Document", "Status", "Source material that already exists"],
        ["FRS &mdash; Feature Requirement Spec", NONE(), "Would be written from the product's "
         "behaviour and CLAUDE.md. No current equivalent."],
        ["ARD &mdash; Architecture Requirements", PART(),
         "AICyberAuditBox_Complete_Architecture_Implementation_And_Rationale_Master_Report.pdf, "
         "Azure_High_Core_Multi_Instance_Architecture_Proposal.pdf."],
        ["System Design Workflow", PART(),
         "Scoping_and_Validator_Architecture_Report.pdf; the 4-gate validator description "
         "in CLAUDE.md."],
        ["HLD", PART(), "AICyberAuditBox_Technical_Reference.pdf (138 KB) is the closest thing."],
        ["LLD", NONE(), "Nothing at this level. The code comments are unusually detailed and "
                        "are the best raw material."],
        ["ICD &mdash; Internal and External", NONE(),
         "The FastAPI app already produces an OpenAPI schema &mdash; that is the external ICD, "
         "and it can be exported in CI rather than written by hand."],
        ["Configurations", PART(), "config/retrieval_config.json, .env.example, compose "
                                   "environment blocks. Not described in one place."],
        ["System Requirements", PART(),
         "The sizing tables in INSTALL_v3.24.md and docker-compose.customer.yml comments "
         "(RAM per model, slots per core). Needs hardware / software / licence / network "
         "stated as one document."],
    ], [116, 52, 337]))

    s.append(Paragraph("Official", H2))
    s.append(table([
        ["Document", "Status", "Note"],
        ["Product / Application Info", HAVE(), "README.md."],
        ["Release Notes", PART(),
         "The 7 UPDATE_v*.md files are de-facto release notes. Consolidate into one "
         "CHANGELOG with a section per tagged version."],
        ["SBOM", NONE(),
         "<b>The notable gap.</b> This product audits other people's SBOMs (it ships "
         "xbom_sbom_knowledge.json) and has none of its own. Cheapest fix in this whole "
         "plan: Trivy already runs in CI and emits CycloneDX with one flag."],
        ["Automation Test Cases and Reports", PART(),
         "65 tests exist; qa/ stores JSON results. No published per-release report."],
        ["Cybersecurity Reports / Safe-to-Host", PART(),
         "Semgrep + Trivy SARIF in CI, VAPT_Security_Hardening_Report.pdf at root. A "
         "Safe-to-Host certificate is a formal sign-off document that does not exist yet."],
        ["Quality Certificate and Assurance", NONE(), "Does not exist."],
    ], [116, 52, 337]))

    s.append(Paragraph("Operational", H2))
    s.append(table([
        ["Document", "Status", "Note"],
        ["User Guides", PART(),
         "docs/guides/AICyberAuditBox_User_Guide.html exists but is <b>stale</b> &mdash; "
         "CLAUDE.md records that it predates the Checklist/Control/Selective rename, and "
         "Admin and Auditee sections were never captured."],
        ["System Configuration", PART(), "Spread across INSTALL_v*.md and compose comments."],
        ["MOP &mdash; Method of Procedure", PART(),
         "ROLLING_UPDATE_PLAYBOOK.md is effectively a MOP for upgrades. Rename and expand "
         "to cover install, upgrade, rollback, backup."],
        ["SOP &mdash; Standard Operating Procedure", NONE(), "Does not exist."],
    ], [116, 52, 337]))

    # ==================================================== 4. branching
    s.append(PageBreak())
    s.append(Paragraph("4.  Branching model", H1))
    s.append(table([
        ["Target tier", "Today", "Proposal"],
        ["Development", "<font face='Courier' size='7.5'>Developer</font> &mdash; active",
         "Keep. Feature branches merge here. No direct pushes once QC exists."],
        ["Continuous Integration (main)", "<font face='Courier' size='7.5'>main</font> &mdash; "
         "currently receives direct pushes",
         "Protect it. CI green required; merge via PR only. This is the change that costs "
         "the most habit and buys the most."],
        ["QC-Staging", NONE(),
         "Create <font face='Courier' size='7.5'>qc-staging</font>. Cut from main. This is "
         "what QC tests and what a bundle is built from &mdash; not from a developer's "
         "working tree."],
        ["Production", NONE(),
         "Create <font face='Courier' size='7.5'>production</font>. Only ever "
         "fast-forwarded from qc-staging, and <b>every merge tagged</b>. The tag is what a "
         "customer bundle is built from."],
    ], [96, 150, 259]))
    s.append(Spacer(1, 4))
    s.append(Paragraph(
        "<b>Why this matters here specifically.</b> CLAUDE.md already records the "
        "consequence of not having it: <i>\"no commit represents the shipped v3.23\"</i>. "
        "A bundle was shipped that cannot be reproduced from the repository. A Production "
        "branch with a tag per release is the direct fix.", WARNP))
    s.append(Paragraph(
        "Also housekeeping: the Semgrep auto-fix branch "
        "(<font face='Courier' size='7.5'>devsecops/sast-fix/...</font>) and "
        "<font face='Courier' size='7.5'>mcp-integration-v2</font> should be merged or "
        "deleted &mdash; a long-lived branch nobody owns becomes a question at audit time.",
        NOTE))

    # ==================================================== 5. versioning
    s.append(Paragraph("5.  Compilation, bundling and checksum", H1))
    s.append(Paragraph("Today the bundler produces:", BODY))
    s.append(Paragraph("AICyberAuditBox-3.22-complete.tar", CODE))
    s.append(Paragraph(
        "No branch, no timestamp, no checksum. Two bundles built a month apart from "
        "different code are indistinguishable by name. Target naming:", BODY))
    s.append(Paragraph(
        "AICyberAuditBox_&lt;BRANCH&gt;_v&lt;MAJOR&gt;.&lt;MINOR&gt;.&lt;PATCH&gt;_&lt;YYYYMMDD-HHMM&gt;.tar<br/>"
        "<br/>"
        "AICyberAuditBox_PROD_v3.25.0_20260916-1430.tar<br/>"
        "AICyberAuditBox_PROD_v3.25.0_20260916-1430.tar.sha256<br/>"
        "AICyberAuditBox_PROD_v3.25.1-hotfix_20260918-0915.tar", CODE))
    s.append(table([
        ["Element", "Rule"],
        ["MAJOR", "Breaking change to data, licence or deployment shape."],
        ["MINOR", "New capability, backward compatible."],
        ["PATCH", "Fix only. A code-only patch bundle is already supported "
                  "(<font face='Courier' size='7.5'>--patch</font>, ~6 MB)."],
        ["hotfix", "Out-of-cycle fix against a Production tag."],
        ["Checksum", "SHA-256 sidecar written beside the tar, plus a MANIFEST listing every "
                     "image tag and its digest. <b>Not currently produced &mdash; add to "
                     "build_customer_bundle.py.</b> The customer's install script should "
                     "verify it before extracting."],
    ], [66, 439]))

    # ==================================================== 6-10
    s.append(PageBreak())
    s.append(Paragraph("6.  Pipeline, signing, security, backup, automation", H1))

    s.append(Paragraph("Pipeline (5) and Automation (10)", H2))
    s.append(Paragraph(
        "Six workflows exist; the problem is trigger coverage, not absence. "
        "<font face='Courier' size='7.5'>e2e</font>, "
        "<font face='Courier' size='7.5'>ai-eval</font>, "
        "<font face='Courier' size='7.5'>load-test</font> and "
        "<font face='Courier' size='7.5'>deploy</font> are manual-only, so the expensive "
        "checks run when someone remembers. Proposal:", BODY))
    s.append(table([
        ["Branch event", "What should run automatically"],
        ["PR into Developer", "lint + unit tests + Semgrep (fast gate, minutes)"],
        ["Merge to main", "full CI + Trivy + SBOM generation + publish test report"],
        ["Merge to qc-staging", "e2e (Playwright) + ai-eval + load-test &mdash; the three that "
                                "are manual today"],
        ["Tag on production", "build images, sign, bundle, checksum, attach to a GitHub Release"],
    ], [110, 395]))

    s.append(Paragraph("Containerization and signing (6)", H2))
    s.append(Paragraph(
        "No signing today. Add <b>cosign</b> at the tag-on-production step: sign each of the "
        "four product images, and sign the bundle tar. For an air-gapped customer this is "
        "what converts 'a tar someone handed us' into 'a tar we can verify came from you' "
        "&mdash; they verify the signature offline against your public key, exactly as they "
        "already verify the licence key. Use keyless/OIDC only if the customer can reach "
        "Fulcio; otherwise a long-lived key pair, with the private half in a secret manager.",
        BODY))
    s.append(Paragraph(
        "Note the precedent already in this repo: the licence signing key was lost because it "
        "was generated into a temp folder. Whatever key is created for cosign needs a "
        "custody decision made at the same time it is generated, not afterwards.", WARNP))

    s.append(Paragraph("Cyber security (8)", H2))
    s.append(Paragraph(
        "Semgrep, Trivy (fs / image / config) and Dependabot are in place, and the four open "
        "Dependabot alerts were cleared on 16 Sep 2026. Add: SBOM in CycloneDX from the Trivy "
        "run already happening, a Safe-to-Host document per release, and a documented "
        "triage SLA so an alert has an owner and a deadline rather than sitting open.", BODY))

    s.append(Paragraph("Backup and restore (9)", H2))
    s.append(Paragraph(
        "<font face='Courier' size='7.5'>run_all.bat</font> already dumps the database on "
        "every start (<font face='Courier' size='7.5'>backups/shakthidb_master_*.sql</font>), "
        "and replication to two slaves runs. What is missing is the other half: a written, "
        "<b>tested</b> restore procedure, a retention rule, and a statement of RPO/RTO. An "
        "untested backup is an assumption. This belongs in the MOP.", BODY))
    s.append(Paragraph(
        "Related and worth fixing while here: the id-sequence desync repaired on 16 Sep 2026 "
        "was caused by restoring a dump without realigning sequences &mdash; which is exactly "
        "the kind of defect a rehearsed restore would have caught years earlier.", NOTE))

    # ==================================================== order
    s.append(PageBreak())
    s.append(Paragraph("7.  Order of adoption", H1))
    s.append(Paragraph(
        "Sequenced by risk. Everything in phases 1&ndash;3 is additive and cannot break a "
        "running build. Phase 4 is the only one that touches code paths.", BODY))
    s.append(table([
        ["Phase", "Work", "Risk"],
        ["1 &mdash; free",
         "Create the <font face='Courier' size='7.5'>Documentation/</font> tree "
         "(Design, Official, Operational) and move the loose root PDFs into it. Consolidate "
         "UPDATE_v*.md into one CHANGELOG. Delete or merge the two stale branches.",
         "<font color='%s'><b>None.</b></font> No code reads these paths." % OK.hexval()],
        ["2 &mdash; cheap, high value",
         "Add SBOM generation to the existing Trivy job. Add SHA-256 + MANIFEST to "
         "build_customer_bundle.py and verification to install.sh/.bat. Create "
         "<font face='Courier' size='7.5'>qc-staging</font> and "
         "<font face='Courier' size='7.5'>production</font>; protect "
         "<font face='Courier' size='7.5'>main</font>; adopt the version naming.",
         "<font color='%s'><b>Low.</b></font> Additive to CI and to the bundler." % OK.hexval()],
        ["3 &mdash; writing, not engineering",
         "Author the missing documents: FRS, LLD, SOP, Safe-to-Host, Quality Certificate, "
         "System Requirements. Export the OpenAPI schema in CI as the external ICD. Refresh "
         "the stale User Guide. Build the TPS register (open-source licences, incl. Gemma "
         "weights).",
         "<font color='%s'><b>None</b> to the product; this is effort, not risk.</font>" % OK.hexval()],
        ["4 &mdash; last, deliberately",
         "Physically move <font face='Courier' size='7.5'>src/</font> under "
         "<font face='Courier' size='7.5'>Source/Application/</font>, with TPS, Tools and "
         "Target alongside.",
         "<font color='%s'><b>High.</b></font> See below." % GAP.hexval()],
    ], [80, 300, 125]))

    s.append(Spacer(1, 5))
    s.append(Paragraph("Why moving src/ is the risky one", H2))
    s.append(Paragraph(
        "The path <font face='Courier' size='8'>src/</font> is not just a folder name here. "
        "It is load-bearing in at least six places:", BODY))
    s.append(table([
        ["What", "Where"],
        ["<font face='Courier' size='7.5'>COPY src/ /app/src/</font>", "Dockerfile.app"],
        ["<font face='Courier' size='7.5'>PYTHONPATH=/app</font> and "
         "<font face='Courier' size='7.5'>uvicorn src.api.main:app</font>", "Dockerfile.app CMD"],
        ["<font face='Courier' size='7.5'>StaticFiles(directory=\"src/api/static\")</font> "
         "&mdash; a <b>relative</b> path resolved from the working directory",
         "src/api/main.py:122, and FileResponse at :131"],
        ["15 <font face='Courier' size='7.5'>__file__</font>-relative data loads "
         "(knowledge JSON, report assets, embeddings cache)", "across src/core and src/api"],
        ["<font face='Courier' size='7.5'>shutil.copytree(\"src\")</font> when building a "
         "patch bundle", "build_customer_bundle.py"],
        ["Import paths in 65 tests", "tests/, qa/"],
    ], [250, 255]))
    s.append(Spacer(1, 4))
    s.append(Paragraph(
        "None of this is hard, but it must be one atomic commit with the full suite run "
        "afterwards &mdash; and it should not be done in the same release as a customer "
        "bundle. If the structure is needed for compliance sooner than that, the cheaper "
        "option is to adopt the Documentation, TPS, Tools and Target trees now and record "
        "<font face='Courier' size='8'>src/</font> as the Source tree in a mapping table, "
        "deferring the physical move to a quiet release.", WARNP))

    s.append(Spacer(1, 8))
    s.append(Paragraph("Proposed final layout", H2))
    s.append(Paragraph(
        "AICyber_Audit_Box/<br/>"
        "&nbsp;&nbsp;Source/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
        "Configurations_Property/ Common/ Application/ Reference_Dependencies/<br/>"
        "&nbsp;&nbsp;TPS/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
        "Open_Source/ Commercials/<br/>"
        "&nbsp;&nbsp;Tools/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
        "Scripts/{Home_Grown,Third_Party}/ Direct_Bundling_Content/ Product_Application_Docs/<br/>"
        "&nbsp;&nbsp;Target/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
        "Binaries/ Libraries/&nbsp;&nbsp;&nbsp;&nbsp;(generated, gitignored)<br/>"
        "&nbsp;&nbsp;Documentation/&nbsp;&nbsp;&nbsp;Design/ Official/ Operational/<br/>"
        "&nbsp;&nbsp;.github/workflows/", TREE))

    s.append(Spacer(1, 10))
    s.append(Paragraph(
        "Prepared 16 September 2026 against commit 0f83512 on "
        "AISecurityComplianceAuditOps/AICyber_Audit_Box. No repository content was modified "
        "in producing this document.", NOTE))

    doc.build(s)
    print("Wrote " + OUT)


if __name__ == "__main__":
    build()
