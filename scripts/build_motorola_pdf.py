"""
build_motorola_pdf.py
Loads findings from scratch/motorola_audit_results.json and generates the PDF report.
"""

import os
import json
import datetime
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# ── Color Palette ──────────────────────────────────────────────────────────
DARK_BG      = (15,  23,  42)    # slate-900
ACCENT_BLUE  = (59, 130, 246)    # blue-500
ACCENT_GREEN = (34, 197,  94)    # green-500
ACCENT_AMBER = (245, 158,  11)   # amber-500
ACCENT_RED   = (239,  68,  68)   # red-500
WHITE        = (255, 255, 255)
LIGHT_GRAY   = (241, 245, 249)
MID_GRAY     = (148, 163, 184)
DARK_TEXT    = (15,  23,  42)
BODY_TEXT    = (51,  65,  85)

class AuditReportPDF(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_fill_color(*DARK_BG)
        self.rect(0, 0, 210, 12, "F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*MID_GRAY)
        self.set_xy(10, 3)
        self.cell(0, 6, "ISO 27001 Compliance Audit  |  Motorola Global Incident Response Plan", align="L")
        self.set_xy(0, 3)
        self.cell(200, 6, f"Page {self.page_no()}", align="R")
        self.ln(12)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-12)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*MID_GRAY)
        self.cell(0, 6, "CONFIDENTIAL -- Internal Compliance Audit Report", align="C")

    def hline(self, color=LIGHT_GRAY, thickness=0.3):
        self.set_draw_color(*color)
        self.set_line_width(thickness)
        y = self.get_y()
        self.line(10, y, 200, y)
        self.ln(3)

    def section_title(self, text):
        self.ln(4)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*DARK_BG)
        self.cell(0, 8, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.hline(ACCENT_BLUE, 0.6)

    def body(self, text, size=9, color=BODY_TEXT, indent=0):
        self.set_font("Helvetica", "", size)
        self.set_text_color(*color)
        self.set_x(10 + indent)
        self.multi_cell(190 - indent, 5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def kv(self, key, value):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*DARK_BG)
        self.set_x(10)
        kw = self.get_string_width(key + "  ")
        self.cell(kw, 5, key)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*BODY_TEXT)
        self.multi_cell(0, 5, value, new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def generate_pdf(results_quick, results_deep, execution_stats):
    pdf = AuditReportPDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.set_margins(10, 14, 10)

    # ════════════════════════════════════════════
    # PAGE 1 — COVER
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.set_fill_color(*DARK_BG)
    pdf.rect(0, 0, 210, 297, "F")

    pdf.set_fill_color(*ACCENT_BLUE)
    pdf.rect(0, 110, 210, 3, "F")

    pdf.set_xy(0, 50)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(*WHITE)
    pdf.cell(210, 12, "ISO 27001 COMPLIANCE AUDIT", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(*ACCENT_BLUE)
    pdf.cell(210, 10, "Motorola Solutions Global Incident Response Plan", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.ln(6)
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(*MID_GRAY)
    pdf.cell(210, 6, "Audit of Incident Management controls (5.24 - 5.28)", align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Summary box
    pdf.set_fill_color(30, 41, 59)
    pdf.rect(25, 122, 160, 85, "F")
    y0 = 126
    
    # Calculate compliant/partial metrics from deep audit
    deep_statuses = [r.get("status") for r in results_deep]
    compliant_count = sum(1 for s in deep_statuses if s == "COMPLIANT")
    partial_count = sum(1 for s in deep_statuses if s in ("PARTIAL", "PARTIAL_COMPLIANT"))
    non_compliant_count = sum(1 for s in deep_statuses if s == "NON_COMPLIANT")

    metrics = [
        ("Document Evaluated",  "Motorola Solutions Global IRP v2.1"),
        ("Controls Audited",     "ISO 27001: 5.24, 5.25, 5.26, 5.27, 5.28"),
        ("Compliance Status",   f"{compliant_count} Compliant, {partial_count} Partially Compliant, {non_compliant_count} Non-Compliant"),
        ("Quick Audit Time",    f"{execution_stats['quick_total']:.1f} seconds"),
        ("Deep Audit Time",     f"{execution_stats['deep_total']:.1f} seconds"),
        ("AI Model Backend",    "Gemma 4 (4B) via llama-server.exe"),
        ("Report Date",         datetime.date.today().strftime("%B %d, %Y")),
    ]
    for label, value in metrics:
        pdf.set_xy(30, y0)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*MID_GRAY)
        pdf.cell(58, 8, label.upper(), align="L")
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*WHITE)
        pdf.cell(90, 8, value, align="L")
        y0 += 9

    pdf.set_fill_color(*ACCENT_BLUE)
    pdf.rect(0, 280, 210, 17, "F")
    pdf.set_xy(0, 284)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*WHITE)
    pdf.cell(210, 6, "CONFIDENTIAL -- Compliance Audit Report", align="C")

    # ════════════════════════════════════════════
    # PAGE 2 — EXECUTIVE SUMMARY + COMPARISON
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("1. Executive Summary")

    intro = (
        "This compliance report documents the security audit of the Motorola Solutions Global Incident "
        "Response Plan (Version 2.1, April 2022) against the ISO 27001:2022 standard. The audit specifically "
        "focuses on the core incident management controls under Clause 5 (Organizational Controls):\n"
        "- 5.24: Incident Management Planning and Preparation\n"
        "- 5.25: Assessment and Decision on Information Security Events\n"
        "- 5.26: Response to Information Security Incidents\n"
        "- 5.27: Learning from Information Security Incidents\n"
        "- 5.28: Collection of Evidence\n\n"
        "To evaluate the auditor engine's effectiveness, the document was audited in both Quick and Deep "
        "modes. The Quick Audit executes the analysis in a single pass without verification/self-correction. "
        "The Deep Audit utilizes the LangGraph multi-gate validator pipeline, executing up to 2 self-correction "
        "passes on CPU when grounding verification fails. Both audits found the document has strong coverage for "
        "planning, assessment, and response roles, but identified minor procedural compliance gaps in evidence collection "
        "standards."
    )
    pdf.body(intro)
    pdf.ln(2)

    pdf.section_title("2. Quick vs. Deep Audit Comparison Table")

    # Header
    col_w = [14, 60, 32, 32, 26, 26]
    hdrs  = ["ID", "Control Name", "Quick Status", "Deep Status", "Quick Time", "Deep Time"]
    pdf.set_fill_color(*DARK_BG)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 8)
    for w, h in zip(col_w, hdrs):
        pdf.cell(w, 7, h, fill=True, align="C")
    pdf.ln()

    status_colors = {
        "COMPLIANT":        ACCENT_GREEN,
        "PARTIAL":          ACCENT_AMBER,
        "PARTIAL_COMPLIANT": ACCENT_AMBER,
        "NON_COMPLIANT":    ACCENT_RED,
    }

    for i in range(len(results_quick)):
        rq = results_quick[i]
        rd = results_deep[i]
        
        bg = WHITE if i % 2 == 0 else LIGHT_GRAY
        pdf.set_fill_color(*bg)
        pdf.set_text_color(*DARK_TEXT)
        pdf.set_font("Helvetica", "B", 8)
        
        cid = rq["control_id"].split(" ")[0]
        pdf.cell(col_w[0], 8, cid, fill=True, align="C")
        
        pdf.set_font("Helvetica", "", 7.5)
        cname = rq["control_name"]
        if len(cname) > 36:
            cname = cname[:33] + "..."
        pdf.cell(col_w[1], 8, cname, fill=True)
        
        # Quick Status
        q_stat = rq["status"]
        pdf.set_fill_color(*status_colors.get(q_stat, MID_GRAY))
        pdf.set_text_color(*WHITE)
        pdf.set_font("Helvetica", "B", 7)
        pdf.cell(col_w[2], 8, q_stat, fill=True, align="C")
        
        # Deep Status
        d_stat = rd["status"]
        pdf.set_fill_color(*status_colors.get(d_stat, MID_GRAY))
        pdf.set_text_color(*WHITE)
        pdf.set_font("Helvetica", "B", 7)
        pdf.cell(col_w[3], 8, d_stat, fill=True, align="C")
        
        # Restore row background
        pdf.set_fill_color(*bg)
        pdf.set_text_color(*DARK_TEXT)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(col_w[4], 8, f"{rq['elapsed']:.1f}s", fill=True, align="C")
        pdf.cell(col_w[5], 8, f"{rd['elapsed']:.1f}s", fill=True, align="C")
        pdf.ln()

    # ════════════════════════════════════════════
    # PAGE 3 — DETAILED COMPLIANCE FINDINGS (1)
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("3. Detailed Control Findings (Deep Audit)")

    # Print first 3 controls
    for i in range(3):
        res = results_deep[i]
        sc = status_colors.get(res["status"], MID_GRAY)
        
        y_row = pdf.get_y()
        pdf.set_fill_color(*sc)
        pdf.rect(10, y_row, 4, 10, "F")
        pdf.set_fill_color(*LIGHT_GRAY)
        pdf.rect(14, y_row, 186, 10, "F")
        pdf.set_xy(16, y_row + 2)
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.set_text_color(*DARK_BG)
        pdf.cell(0, 6, f"{res['control_id']}  |  {res['control_name']}")
        pdf.ln(12)

        pdf.kv("Status: ", res["status"])
        pdf.kv("Severity: ", res["severity"])
        
        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*DARK_BG)
        pdf.set_x(10)
        pdf.cell(0, 4, "Evidence / Input Document Citation:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_fill_color(224, 231, 245)
        pdf.set_x(12)
        pdf.set_font("Helvetica", "I", 7.5)
        pdf.set_text_color(50, 50, 80)
        quote = res.get("evidence_quote") or "No direct evidence citation found."
        
        # Replace smart quotes in quote to prevent PDF build failures
        quote = quote.replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"')
        pdf.multi_cell(186, 4.5, f"\"{quote}\"", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*DARK_BG)
        pdf.set_x(10)
        pdf.cell(0, 4, "Auditor Analysis & Gaps:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*BODY_TEXT)
        pdf.set_x(12)
        reasoning = res.get("reasoning") or "No detailed analysis available."
        pdf.multi_cell(186, 4, reasoning, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*DARK_BG)
        pdf.set_x(10)
        pdf.cell(0, 4, "Recommendation:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*BODY_TEXT)
        pdf.set_x(12)
        rec = res.get("recommendation") or "No recommendation provided."
        pdf.multi_cell(186, 4, rec, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.ln(3)
        pdf.hline()

    # ════════════════════════════════════════════
    # PAGE 4 — DETAILED COMPLIANCE FINDINGS (2)
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("3. Detailed Control Findings (Deep Audit - Continued)")

    # Print remaining 2 controls (5.27 and 5.28)
    for i in range(3, 5):
        res = results_deep[i]
        sc = status_colors.get(res["status"], MID_GRAY)
        
        y_row = pdf.get_y()
        pdf.set_fill_color(*sc)
        pdf.rect(10, y_row, 4, 10, "F")
        pdf.set_fill_color(*LIGHT_GRAY)
        pdf.rect(14, y_row, 186, 10, "F")
        pdf.set_xy(16, y_row + 2)
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.set_text_color(*DARK_BG)
        pdf.cell(0, 6, f"{res['control_id']}  |  {res['control_name']}")
        pdf.ln(12)

        pdf.kv("Status: ", res["status"])
        pdf.kv("Severity: ", res["severity"])
        
        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*DARK_BG)
        pdf.set_x(10)
        pdf.cell(0, 4, "Evidence / Input Document Citation:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_fill_color(224, 231, 245)
        pdf.set_x(12)
        pdf.set_font("Helvetica", "I", 7.5)
        pdf.set_text_color(50, 50, 80)
        quote = res.get("evidence_quote") or "No direct evidence citation found."
        quote = quote.replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"')
        pdf.multi_cell(186, 4.5, f"\"{quote}\"", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*DARK_BG)
        pdf.set_x(10)
        pdf.cell(0, 4, "Auditor Analysis & Gaps:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*BODY_TEXT)
        pdf.set_x(12)
        reasoning = res.get("reasoning") or "No detailed analysis available."
        pdf.multi_cell(186, 4, reasoning, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*DARK_BG)
        pdf.set_x(10)
        pdf.cell(0, 4, "Recommendation:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*BODY_TEXT)
        pdf.set_x(12)
        rec = res.get("recommendation") or "No recommendation provided."
        pdf.multi_cell(186, 4, rec, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.ln(3)
        pdf.hline()

    # ════════════════════════════════════════════
    # PAGE 5 — TECH SPEC & RECOMMENDATIONS
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("4. Technical Audit Metrics")

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*DARK_BG)
    pdf.cell(70, 6, "Metric Name")
    pdf.cell(40, 6, "Quick Audit")
    pdf.cell(40, 6, "Deep Audit")
    pdf.cell(40, 6, "Variance / Impact")
    pdf.ln()
    pdf.hline(DARK_BG, 0.5)

    metrics_tech = [
        ("Total Evaluation Time", f"{execution_stats['quick_total']:.1f}s", f"{execution_stats['deep_total']:.1f}s", f"+{(execution_stats['deep_total'] - execution_stats['quick_total']):.1f}s (reflection CPU load)"),
        ("Average Time Per Control", f"{execution_stats['quick_avg']:.1f}s", f"{execution_stats['deep_avg']:.1f}s", f"+{(execution_stats['deep_avg'] - execution_stats['quick_avg']):.1f}s per control"),
        ("Validation Gate Checks", "1 pass", "Multi-gate (3)", "Grounding & Leakage check active"),
        ("Self-Correction Retries", "Disabled", f"{execution_stats['deep_retries']} triggered", "Corrects fuzzy/hallucinated quotes"),
    ]
    for m, q, d, v in metrics_tech:
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*DARK_BG)
        pdf.cell(70, 6, m)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*BODY_TEXT)
        pdf.cell(40, 6, q)
        pdf.cell(40, 6, d)
        pdf.set_font("Helvetica", "I", 8)
        pdf.cell(40, 6, v)
        pdf.ln()
    pdf.ln(4)

    pdf.section_title("5. Compliance Recommendations & Next Steps")
    
    recs = [
        ("Define Forensic Preservation Standards (5.28)",
         "While the document notes helpdesk and SOC personnel assist in data collection, it lacks a formal, legally "
         "admissible chain of custody and forensic data preservation guideline. Establish a forensic runbook specifying "
         "hash verification (e.g., SHA-256) for collected image/log evidence."),
        ("Formalize incident learning review timelines (5.27)",
         "The GRC team is tasked with owning the 'after-action-review' process, but there are no strict SLAs or templates "
         "for executing post-incident review (PIR) reports. Mandate a timeline (e.g., within 5 business days for major incidents) "
         "and define a standardized PIR template."),
        ("Incorporate lessons learned back into BCP/DR (5.27)",
         "Add a feedback loop that requires lessons learned from security incidents to be explicitly reviewed by the EIS "
         "team during the bi-annual policy updates to revise recovery runbooks."),
        ("Configure automatic alerting rules for SOC (5.25)",
         "Define specific indicators of compromise (IoCs) and event correlation rules to automate the transition from "
         "'Event' to 'Alert' to 'Incident' within the SOC ticketing system, minimizing manual triage delay.")
    ]
    for i, (title, detail) in enumerate(recs, 1):
        pdf.set_x(10)
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.set_text_color(*ACCENT_BLUE)
        pdf.cell(0, 6, f"{i}.  {title}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_x(14)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*BODY_TEXT)
        pdf.multi_cell(186, 5, detail, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

    # Save
    output_pdf_path = "motorola_audit_report.pdf"
    pdf.output(output_pdf_path)
    print(f"[INFO] PDF report successfully generated at: {os.path.abspath(output_pdf_path)}")


def main():
    # Load JSON findings
    results_path = "scratch/motorola_audit_results.json"
    with open(results_path, encoding="utf-8") as f:
        data = json.load(f)
    
    results_quick = data["quick"]
    results_deep = data["deep"]
    stats = data["stats"]
    
    generate_pdf(results_quick, results_deep, stats)


if __name__ == "__main__":
    main()
