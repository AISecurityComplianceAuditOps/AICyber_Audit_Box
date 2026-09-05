"""Fix Unicode characters in run_motorola_audit.py to prevent FPDF errors."""
import os

path = os.path.join(os.path.dirname(__file__), "run_motorola_audit.py")

with open(path, encoding="utf-8") as f:
    text = f.read()

replacements = [
    ("\u2014", "--"),   # em dash
    ("\u2013", "-"),    # en dash
    ("\u00b7", "|"),    # middle dot
    ("\u2019", "'"),    # right single quote
    ("\u2018", "'"),    # left single quote
    ("\u201c", '"'),    # left double quote
    ("\u201d", '"'),    # right double quote
    ("", " "),         # replacement character
]

for old, new in replacements:
    text = text.replace(old, new)

with open(path, "w", encoding="utf-8") as f:
    f.write(text)

print("Unicode characters in run_motorola_audit.py fixed.")
