"""Fix Unicode characters in generate_eval_pdf.py that are not supported by fpdf2's built-in fonts."""
import os

path = os.path.join(os.path.dirname(__file__), "generate_eval_pdf.py")

with open(path, encoding="utf-8") as f:
    text = f.read()

replacements = [
    ("\u2014", "--"),   # em dash
    ("\u2013", "-"),    # en dash
    ("\u2019", "'"),    # right single quotation mark
    ("\u2018", "'"),    # left single quotation mark
    ("\u201c", '"'),    # left double quotation mark
    ("\u201d", '"'),    # right double quotation mark
    ("\u2022", "*"),    # bullet
    ("\u2212", "-"),    # minus sign
    ("\u00a0", " "),    # non-breaking space
]

for old, new in replacements:
    text = text.replace(old, new)

with open(path, "w", encoding="utf-8") as f:
    f.write(text)

print("Unicode characters replaced successfully.")
