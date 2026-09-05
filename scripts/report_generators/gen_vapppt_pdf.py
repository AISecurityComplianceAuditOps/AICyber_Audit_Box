# -*- coding: utf-8 -*-
from fpdf import FPDF
from fpdf.enums import XPos, YPos
import os

class MarkdownPDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(100, 116, 139)
        self.cell(0, 8, 'VAPT Audit Engine - Architecture, Implementations & Technical Fixes', align='R', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(4)
        
    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', '', 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 8, f'Page {self.page_no()}', align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

def clean(val):
    if not val:
        return ""
    val = str(val).replace('—', '-').replace('–', '-').replace('•', '*').replace('’', "'").replace('“', '"').replace('”', '"')
    val = val.encode('latin-1', 'replace').decode('latin-1')
    return val

def generate_pdf():
    pdf = MarkdownPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()

    with open('vapppt.md', 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line in lines:
        line_s = line.strip()
        if not line_s:
            pdf.ln(2)
            continue
        if line_s.startswith('# '):
            pdf.set_font('Helvetica', 'B', 15)
            pdf.set_text_color(15, 23, 42)
            pdf.multi_cell(180, 7, clean(line_s[2:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(3)
        elif line_s.startswith('## '):
            pdf.set_font('Helvetica', 'B', 12)
            pdf.set_text_color(30, 41, 59)
            pdf.multi_cell(180, 6, clean(line_s[3:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(2)
        elif line_s.startswith('### '):
            pdf.set_font('Helvetica', 'B', 10)
            pdf.set_text_color(51, 65, 85)
            pdf.multi_cell(180, 5, clean(line_s[4:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1.5)
        else:
            pdf.set_font('Helvetica', '', 8.5)
            pdf.set_text_color(51, 65, 85)
            txt_clean = line_s.replace('**', '').replace('*', '-').replace('|', '  ')
            pdf.multi_cell(180, 4.2, clean(txt_clean), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.output('vapppt.pdf')
    print('SUCCESS: vapppt.pdf created successfully!')

if __name__ == '__main__':
    generate_pdf()
