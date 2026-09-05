# -*- coding: utf-8 -*-
from fpdf import FPDF
from fpdf.enums import XPos, YPos
import os

class BestSetupReportPDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(100, 116, 139)
        self.cell(0, 8, 'AICyberAuditBox - Why Your Setup is the BEST for this Project', align='R', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(226, 232, 240)
        self.line(15, 18, 195, 18)
        self.ln(6)
        
    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', '', 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 8, f'Page {self.page_no()}', align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

def clean(val):
    if not val:
        return ""
    val = str(val).replace('—', '-').replace('–', '-').replace('•', '*').replace('’', "'").replace('“', '"').replace('”', '"')
    val = val.replace('🚀', '[BEST]').replace('🏆', '[TOP]').replace('⚡', '[FAST]').replace('🪶', '[LIGHT]').replace('🎯', '[ACCURATE]').replace('🗄️', '[DB]').replace('🛡️', '[SEC]').replace('📊', '[SUMMARY]').replace('✅', '[YES]').replace('❌', '[NO]').replace('⚠️', '[WARN]')
    val = val.encode('latin-1', 'replace').decode('latin-1')
    return val

def generate_pdf():
    pdf = BestSetupReportPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()

    md_file = 'WHY_MY_SETUP_IS_BEST_FOR_THIS_PROJECT.md'
    if not os.path.exists(md_file):
        print(f"Error: {md_file} not found.")
        return

    with open(md_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    in_code_block = False

    for line in lines:
        line_s = line.strip()
        
        if line_s.startswith('```'):
            in_code_block = not in_code_block
            pdf.ln(1)
            continue
            
        if in_code_block:
            pdf.set_font('Courier', '', 8)
            pdf.set_text_color(51, 65, 85)
            pdf.set_fill_color(241, 245, 249)
            pdf.multi_cell(180, 4.5, clean(line_s), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            continue

        if not line_s:
            pdf.ln(2)
            continue

        if line_s.startswith('# '):
            pdf.set_font('Helvetica', 'B', 15)
            pdf.set_text_color(15, 23, 42)
            pdf.multi_cell(180, 8, clean(line_s[2:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(3)
        elif line_s.startswith('## '):
            pdf.set_font('Helvetica', 'B', 12)
            pdf.set_text_color(30, 41, 59)
            pdf.multi_cell(180, 7, clean(line_s[3:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(2)
        elif line_s.startswith('### '):
            pdf.set_font('Helvetica', 'B', 10.5)
            pdf.set_text_color(51, 65, 85)
            pdf.multi_cell(180, 6, clean(line_s[4:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1.5)
        elif line_s.startswith('* ') or line_s.startswith('- '):
            pdf.set_font('Helvetica', '', 9.5)
            pdf.set_text_color(30, 41, 59)
            pdf.multi_cell(180, 5, "  - " + clean(line_s[2:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        elif line_s.startswith('|'):
            pdf.set_font('Courier', '', 8)
            pdf.set_text_color(15, 23, 42)
            pdf.multi_cell(180, 4.5, clean(line_s), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font('Helvetica', '', 9.5)
            pdf.set_text_color(30, 41, 59)
            pdf.multi_cell(180, 5, clean(line_s), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    output_pdf = 'WHY_MY_SETUP_IS_BEST_FOR_THIS_PROJECT.pdf'
    pdf.output(output_pdf)
    print(f"[SUCCESS] Best Setup PDF generated successfully: {output_pdf}")

if __name__ == '__main__':
    generate_pdf()
