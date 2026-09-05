"""
generate_gap_pdf.py
Compiles the humanized evaluation_gap_analysis.md reports into clean, professional PDFs.
Run: python scripts/generate_gap_pdf.py
"""

import os
from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

class MarkdownPDF(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(148, 163, 184)  # MID_GRAY
        # Left header
        self.cell(0, 5, "AICyberAuditBox  --  Safety & Controls Evaluation", align="L")
        # Right page number
        self.set_x(10)
        self.cell(0, 5, f"Page {self.page_no()}", align="R")
        self.ln(6)
        self.set_draw_color(226, 232, 240)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(148, 163, 184)  # MID_GRAY
        self.cell(0, 6, "CONFIDENTIAL -- AICyberAuditBox Internal Safety Evaluation  |  Page " + str(self.page_no()), align="C")

def compile_md_to_pdf(md_path, pdf_path):
    if not os.path.exists(md_path):
        print(f"Skipping: {md_path} does not exist.")
        return

    print(f"Compiling {md_path}...")
    pdf = MarkdownPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(10, 15, 10)
    pdf.add_page()
    
    with open(md_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    in_code_block = False
    code_text = []
    
    in_table = False
    table_headers = []
    table_rows = []
    
    # style helpers
    hdr_style = FontFace(emphasis="B", color=(255, 255, 255), fill_color=(15, 23, 42))
    bold_style = FontFace(emphasis="B")
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Code blocks (ASCII Diagram)
        if line.startswith("```"):
            if in_code_block:
                in_code_block = False
                diagram_text = "\n".join(code_text)
                
                # Render ASCII diagram block
                pdf.set_fill_color(248, 250, 252)  # slate-50
                pdf.set_text_color(15, 23, 42)
                pdf.set_font("Courier", "", 8.5)
                
                # calculate box height to prevent orphaned diagrams
                line_h = 4.5
                needed_h = (diagram_text.count("\n") + 1) * line_h + 8
                if pdf.h - pdf.b_margin - pdf.get_y() < needed_h:
                    pdf.add_page()
                
                pdf.set_x(10)
                pdf.multi_cell(190, line_h, diagram_text, fill=True, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.ln(4)
                code_text = []
            else:
                in_code_block = True
            i += 1
            continue
            
        if in_code_block:
            code_text.append(lines[i].rstrip("\n"))
            i += 1
            continue
            
        # Table parsing
        if line.startswith("|"):
            in_table = True
            parts = [p.strip() for p in line.split("|")[1:-1]]
            
            # Skip divider line (e.g., | :--- | :--- |)
            if all(p.startswith(":") or p.startswith("-") or p.endswith("-") for p in parts if p):
                i += 1
                continue
                
            if not table_headers:
                table_headers = parts
            else:
                # Clean up markdown formatting symbols inside cells
                cleaned_parts = [p.replace("**", "").replace("`", "") for p in parts]
                table_rows.append(cleaned_parts)
            i += 1
            continue
        elif in_table:
            # Render the accumulated table rows
            in_table = False
            if table_headers:
                n_cols = len(table_headers)
                
                # Assign column widths dynamically based on headers
                if n_cols == 4:
                    h_first = table_headers[0].lower()
                    if "control" in h_first:
                        col_w = (32, 45, 98, 15)
                    elif "metric" in h_first:
                        col_w = (32, 45, 98, 15)
                    elif "safety" in h_first:
                        col_w = (42, 42, 91, 15)
                    else:
                        col_w = (35, 45, 95, 15)
                elif n_cols == 3:
                    col_w = (40, 125, 25)
                else:
                    col_w = tuple([190 // n_cols] * n_cols)
                    
                pdf.set_font("Helvetica", "", 8.5)
                cleaned_headers = [h.replace("**", "") for h in table_headers]
                
                with pdf.table(col_widths=col_w, text_align="L") as table:
                    hdr = table.row()
                    for h in cleaned_headers:
                        hdr.cell(h, style=hdr_style)
                    for r_data in table_rows:
                        row = table.row()
                        for c_idx, cell_val in enumerate(r_data):
                            # Cell color coding for Status columns
                            clean_val = cell_val.strip()
                            if clean_val in ("OK", "Pass"):
                                ok_style = FontFace(emphasis="B", color=(22, 163, 74))  # green-600
                                row.cell(cell_val, style=ok_style)
                            elif clean_val in ("Gap", "Fail"):
                                gap_style = FontFace(emphasis="B", color=(220, 38, 38))  # red-600
                                row.cell(cell_val, style=gap_style)
                            elif c_idx == 0:
                                row.cell(cell_val, style=bold_style)
                            else:
                                row.cell(cell_val)
                pdf.ln(4)
                table_headers = []
                table_rows = []
            # Proceed to evaluate current line in normal flow (do not skip)
            
        # Empty space line
        if not line:
            i += 1
            continue
            
        # Section Headers
        if line.startswith("# "):
            title = line[2:].strip()
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 18)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(2)
            i += 1
            continue
        elif line.startswith("## "):
            sec_title = line[3:].strip()
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 8, sec_title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            # Accent underline bar
            pdf.set_draw_color(59, 130, 246)  # blue-500
            pdf.set_line_width(0.6)
            y = pdf.get_y()
            pdf.line(10, y, 200, y)
            pdf.ln(3)
            i += 1
            continue
        elif line.startswith("### "):
            sub_title = line[4:].strip()
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 10.5)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 6, sub_title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)
            i += 1
            continue
            
        # Bullet list parsing
        if line.startswith("* ") or line.startswith("- ") or line.startswith("o "):
            bullet_text = line[2:].strip()
            pdf.set_font("Helvetica", "", 9.5)
            pdf.set_text_color(51, 65, 85)
            pdf.set_x(14)
            pdf.cell(4, 5, chr(149), align="L")
            
            # Inline bold formatting within list items
            parts = bullet_text.split("**")
            pdf.set_x(18)
            for p_idx, part in enumerate(parts):
                if p_idx % 2 == 1:
                    pdf.set_font("Helvetica", "B", 9.5)
                    pdf.write(5, part)
                else:
                    pdf.set_font("Helvetica", "", 9.5)
                    pdf.write(5, part)
            pdf.ln(5.5)
            i += 1
            continue
            
        # Separator line
        if line == "---":
            pdf.ln(2)
            pdf.set_draw_color(226, 232, 240)
            pdf.set_line_width(0.4)
            y = pdf.get_y()
            pdf.line(10, y, 200, y)
            pdf.ln(3)
            i += 1
            continue
            
        # Paragraph text with basic bold parser
        text_content = line.replace("`", "")
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(51, 65, 85)
        pdf.set_x(10)
        
        parts = text_content.split("**")
        for p_idx, part in enumerate(parts):
            if p_idx % 2 == 1:
                pdf.set_font("Helvetica", "B", 9.5)
                pdf.write(5, part)
            else:
                pdf.set_font("Helvetica", "", 9.5)
                pdf.write(5, part)
        pdf.ln(5.5)
        
        i += 1
        
    pdf.output(pdf_path)
    print(f"Saved PDF to: {os.path.abspath(pdf_path)}")

def main():
    # Compile the workspace file
    compile_md_to_pdf(
        "c:/Users/HP/Desktop/llama,cpp/au/evaluation_gap_analysis.md",
        "c:/Users/HP/Desktop/llama,cpp/au/EVALUATION_GAP_ANALYSIS.pdf"
    )
    
    # Compile the OneDrive file
    compile_md_to_pdf(
        "c:/Users/HP/OneDrive/evaluation_gap_analysis.md",
        "c:/Users/HP/OneDrive/evaluation_gap_analysis.pdf"
    )

if __name__ == "__main__":
    main()
