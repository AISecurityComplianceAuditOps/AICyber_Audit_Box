# -*- coding: utf-8 -*-
"""Every file type the product accepts must reach the VAPT parsers.

    pytest tests/test_vapt_file_type_matrix.py -v

WHY THIS EXISTS

Asked to confirm every VAPT file type works, one findings table was built in
23 extensions and each run through extract_text() and parse_tool_file() the
way the worker does. Six failed, and none of them said so:

    .webp .bmp .tiff .tif   [Error parsing file report.tiff: File is not a zip file]
    .md .sarif              [Error parsing file report.md:   File is not a zip file]
    .xml                    extracted, then 0 findings

The first five share a cause. extract_text() has a branch per extension and a
final `else` that assumes Word, so anything unlisted is opened as a .docx and
fails as one. bg_worker already treated WEBP, BMP and TIFF as evidence images
-- it lists them in three places -- while extraction only knew PNG and JPEG.
TIFF is what a scanner or a fax produces, which is exactly what an auditor is
handed.

The .xml case is subtler and worse, because it looked like it worked. The XML
branch turns a scan into a readable summary for retrieval, and the tool parsers
recognise a scan by its SCHEMA -- NessusParser looks for NessusClientData_v2.
Digesting the XML hid the schema, so the SAME Nessus export produced a finding
named .nessus and nothing at all named .xml. Burp, ZAP and Nessus itself all
export .xml.
"""
import io
import os
import zipfile

import pytest

from src.core.parsers import parse_tool_file
from src.core.parsers.doc_parsers import extract_text

TITLE = "VAPT Penetration Testing Report"
HEADER = ("Sr. No.", "Vulnerabilities", "Severity", "CVE/CWE", "Recommendation")
ROWS = [
    ("1", "Vertical Privilege Escalation", "High", "CWE-269", "Enforce role-based access control"),
    ("2", "Cryptographic Failure", "High", "CWE-310", "Properly configure the hash"),
    ("3", "Broken Authentication", "High", "CWE-287", "Properly implement authentication"),
    ("4", "Insecure Direct Object Reference", "High", "CWE-639", "Ensure sufficient privilege"),
]
EXPECTED = sorted(r[1] for r in ROWS)
PLAIN = (TITLE + "\n" + "   ".join(HEADER) + "\n"
         + "\n".join("   ".join(r) for r in ROWS) + "\n")

NESSUS_XML = (
    '<?xml version="1.0" ?>\n'
    '<NessusClientData_v2><Report name="scan"><ReportHost name="10.0.0.5">\n'
    '<ReportItem port="443" severity="3" pluginID="42873" '
    'pluginName="SSL Medium Strength Cipher Suites Supported">\n'
    '<synopsis>The remote service supports medium strength SSL ciphers.</synopsis>\n'
    '<solution>Reconfigure the application to avoid medium strength ciphers.</solution>\n'
    '</ReportItem></ReportHost></Report></NessusClientData_v2>\n')

IMAGE_EXT = (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif")


def _run(name, data):
    """extract_text + parse_tool_file, with the worker's OCR re-submit for images."""
    buf = io.BytesIO(data)
    buf.name = name
    text = extract_text(buf) or ""
    assert "[Error parsing" not in text[:200], "%s failed to extract: %s" % (name, text[:120])
    actionable, info = parse_tool_file(name, text, framework="vapt")
    found = actionable + (info if isinstance(info, list) else [])
    if not found and name.lower().endswith(IMAGE_EXT) and text.strip():
        a2, i2 = parse_tool_file("ocr_" + name + ".txt", text, framework="vapt")
        found = a2 + (i2 if isinstance(i2, list) else [])
    return text, found


def _image_bytes(fmt):
    from PIL import Image, ImageDraw, ImageFont
    try:
        font = ImageFont.truetype("arial.ttf", 20)
    except Exception:
        pytest.skip("no TrueType font available to render the table")
    img = Image.new("RGB", (1400, 300), "white")
    d = ImageDraw.Draw(img)
    d.text((20, 14), TITLE, fill="black", font=font)
    y = 60
    d.text((20, y), "   ".join(HEADER), fill="black", font=font)
    y += 34
    for r in ROWS:
        d.text((20, y), "   ".join(r), fill="black", font=font)
        y += 34
    out = io.BytesIO()
    img.convert("RGB").save(out, format=fmt)
    return out.getvalue()


# ── text formats ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ext", [".txt", ".log", ".nmap", ".gnmap", ".md", ".markdown"])
def test_plain_text_formats(ext):
    _text, found = _run("report" + ext, PLAIN.encode("utf-8"))
    assert sorted(f.title for f in found) == EXPECTED, ext


def test_markdown_is_no_longer_opened_as_a_word_document():
    text, _found = _run("notes.md", PLAIN.encode("utf-8"))
    assert "not a zip file" not in text


def test_csv():
    body = (TITLE + "\n" + ",".join(HEADER) + "\n"
            + "\n".join(",".join(r) for r in ROWS) + "\n")
    _text, found = _run("report.csv", body.encode("utf-8"))
    assert sorted(f.title for f in found) == EXPECTED


@pytest.mark.parametrize("ext", [".html", ".htm"])
def test_html(ext):
    html = "<html><body><h1>%s</h1><table><tr>%s</tr>%s</table></body></html>" % (
        TITLE, "".join("<th>%s</th>" % h for h in HEADER),
        "".join("<tr>" + "".join("<td>%s</td>" % v for v in r) + "</tr>" for r in ROWS))
    _text, found = _run("report" + ext, html.encode("utf-8"))
    assert sorted(f.title for f in found) == EXPECTED


def test_json_and_sarif_are_read_as_json():
    """.sarif is what CodeQL, Semgrep and Trivy emit; it was opened as Word."""
    doc = '{"runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[]}]}'
    text, _found = _run("scan.sarif", doc.encode("utf-8"))
    assert "not a zip file" not in text
    assert "semgrep" in text


# ── the XML schema must survive extraction ───────────────────────────────────

def test_a_nessus_export_named_xml_gives_the_same_finding_as_named_nessus():
    """The same bytes produced one finding as .nessus and none as .xml."""
    _t1, as_nessus = _run("scan.nessus", NESSUS_XML.encode("utf-8"))
    _t2, as_xml = _run("scan.xml", NESSUS_XML.encode("utf-8"))
    assert as_nessus, "the .nessus control case itself produced nothing"
    assert [f.title for f in as_xml] == [f.title for f in as_nessus], (
        "the .xml name lost findings the .nessus name produced")


def test_the_xml_summary_is_still_there_for_retrieval():
    """The raw document is appended, not substituted."""
    text, _found = _run("scan.xml", NESSUS_XML.encode("utf-8"))
    assert "[NESSUS SCAN REPORT]" in text or "Host: 10.0.0.5" in text
    assert "NessusClientData_v2" in text


def test_an_oversized_xml_keeps_only_the_summary():
    """Tens of megabytes of scan must not be doubled in memory."""
    from src.core.parsers import doc_parsers
    assert doc_parsers._XML_RAW_APPEND_MAX >= 1024 * 1024, "cap too small for real exports"
    assert doc_parsers._XML_RAW_APPEND_MAX <= 64 * 1024 * 1024, "cap too large to be a cap"


# ── office and pdf ───────────────────────────────────────────────────────────

def test_docx():
    from docx import Document
    d = Document()
    d.add_heading(TITLE, level=1)
    t = d.add_table(rows=1, cols=len(HEADER))
    for i, h in enumerate(HEADER):
        t.rows[0].cells[i].text = h
    for r in ROWS:
        c = t.add_row().cells
        for i, v in enumerate(r):
            c[i].text = v
    out = io.BytesIO()
    d.save(out)
    _text, found = _run("report.docx", out.getvalue())
    assert sorted(f.title for f in found) == EXPECTED


def test_xlsx():
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.append([TITLE])
    ws.append(list(HEADER))
    for r in ROWS:
        ws.append(list(r))
    out = io.BytesIO()
    wb.save(out)
    _text, found = _run("report.xlsx", out.getvalue())
    assert sorted(f.title for f in found) == EXPECTED


def test_pdf():
    pytest.importorskip("reportlab")
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    out = io.BytesIO()
    c = canvas.Canvas(out, pagesize=A4)
    y = 780
    c.drawString(50, y, TITLE)
    y -= 24
    c.drawString(50, y, "   ".join(HEADER))
    y -= 16
    for r in ROWS:
        c.drawString(50, y, "   ".join(r))
        y -= 14
    c.save()
    _text, found = _run("report.pdf", out.getvalue())
    assert sorted(f.title for f in found) == EXPECTED


def test_zip_of_evidence():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("report.txt", PLAIN)
    _text, found = _run("evidence.zip", out.getvalue())
    assert sorted(f.title for f in found) == EXPECTED


# ── images, including the ones that used to be opened as Word ────────────────

@pytest.mark.parametrize("ext,fmt", [
    (".png", "PNG"), (".jpg", "JPEG"), (".jpeg", "JPEG"),
    (".webp", "WEBP"), (".bmp", "BMP"), (".tiff", "TIFF"), (".tif", "TIFF"),
])
def test_every_image_format_the_worker_accepts(ext, fmt):
    text, found = _run("report" + ext, _image_bytes(fmt))
    assert "not a zip file" not in text, "%s was opened as a Word document" % ext
    assert sorted(f.title for f in found) == EXPECTED, (ext, [f.title for f in found])


def test_the_worker_and_the_extractor_agree_on_what_an_image_is():
    """They drifted: the worker listed seven image types, extraction knew three."""
    import re
    src = io.open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "src", "core", "parsers", "doc_parsers.py"),
                  encoding="utf-8").read()
    m = re.search(r'if name_lower\.endswith\(\((?P<exts>[^)]*)\)\):\s*\n\s*try:\s*\n\s*import PIL',
                  src)
    assert m, "image branch not found"
    handled = set(re.findall(r'"(\.[a-z]+)"', m.group("exts")))
    for ext in IMAGE_EXT:
        assert ext in handled, "the worker accepts %s but extraction does not" % ext
