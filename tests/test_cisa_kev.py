"""CVEs known to be exploited in the wild: CISA's KEV catalog.

src/core/knowledge/cisa_kev.json (CC0), built by scripts/build_cisa_kev.py. A
finding whose CVE is in the catalog is marked on the card and in the report; its
severity is never changed. Where the scan or report gave no remediation, CISA's
required action is used, labelled, ahead of the vendor-patch step.
"""
import io
import json
import os
from types import SimpleNamespace

import pytest

from src.core.parsers import control_mapper as cm
from src.core.parsers.finding_schema import Finding

KEV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "src", "core", "knowledge", "cisa_kev.json")
WINRAR = "CVE-2025-6218"          # in the catalog since 2025-12-09
NOT_KEV = "CVE-2024-6387"         # OpenSSH regreSSHion: not in the catalog


def test_the_catalog_ships_with_its_version_and_licence():
    kev = json.load(io.open(KEV_PATH, encoding="utf-8"))
    assert kev["version"] and "CC0" in kev["notice"]
    assert len(kev["cves"]) > 1000 and WINRAR in kev["cves"] and NOT_KEV not in kev["cves"]


def test_only_catalogued_cves_are_marked():
    hits = cm.known_exploited(["CWE-22", WINRAR, NOT_KEV, WINRAR])
    assert [h["cve"] for h in hits] == [WINRAR]
    assert hits[0]["date_added"] == "2025-12-09"
    assert cm.known_exploited([NOT_KEV]) == [] and cm.known_exploited_line([NOT_KEV]) == ""


def test_no_source_remediation_gets_cisas_required_action_then_the_patch():
    f = Finding(title="RARLAB WinRAR < 7.12 Directory Traversal", severity="HIGH", cve_list=[WINRAR])
    text = cm.get_actionable_remediation(f)
    assert text.startswith("Known to be exploited in the wild: CVE-2025-6218 is in CISA's Known Exploited")
    assert "CISA's required action: Apply mitigations per vendor instructions" in text
    assert "Apply the vendor-supplied patch addressing CVE-2025-6218" in text


def test_a_source_remediation_is_kept():
    f = Finding(title="RARLAB WinRAR < 7.12 Directory Traversal", severity="HIGH", cve_list=[WINRAR],
                remediation="Upgrade to WinRAR 7.12 or later.")
    assert "CISA" not in cm.get_actionable_remediation(f)


def test_a_cve_not_in_the_catalog_gets_the_patch_only():
    f = Finding(title="OpenSSH regreSSHion", severity="HIGH", cve_list=[NOT_KEV])
    assert cm.get_actionable_remediation(f).startswith("Apply the vendor-supplied patch addressing CVE-2024-6387")


def test_the_severity_is_never_changed():
    f = Finding(title="RARLAB WinRAR < 7.12 Directory Traversal", severity="LOW", cve_list=[WINRAR])
    cm.map_findings_list([f])
    assert f.severity == "LOW"


def test_the_export_fields_carry_the_kev_line():
    from src.api.endpoints.audit import _vapt_scanner_fields
    row = SimpleNamespace(evidence_snippet="", source_files="scan.nessus", severity_score=0.0, target="10.0.0.5",
                          source_tool="Nessus", confidence=None, cvss_vector=None,
                          cve_refs=f"{WINRAR}, CWE-22")
    got = _vapt_scanner_fields(row)
    assert got["known_exploited"] == ("CVE-2025-6218 is in CISA's Known Exploited Vulnerabilities catalog "
                                      "(listed 2025-12-09; known ransomware use: Unknown)")


def _finding(cves):
    return {"title": "RARLAB WinRAR < 7.12 Directory Traversal", "severity": "HIGH", "severity_score": None,
            "source_tool": "Nessus", "target": "10.0.0.5", "cve_list": cves, "description": "d",
            "remediation": "Upgrade WinRAR.", "status": "Non-Compliant"}


def test_the_pdf_report_marks_a_known_exploited_cve_and_nothing_else():
    pytest.importorskip("fpdf")
    import src.core.report_exporter as rx
    from pypdf import PdfReader
    pdf = rx._export_vapt_pdf("VAPT", [_finding([WINRAR]), _finding([NOT_KEV])], [], "Completed",
                              metadata={"brand_firm": "Dhiware Technologies Pvt Ltd"})
    text = " ".join(" ".join((p.extract_text() or "") for p in PdfReader(io.BytesIO(pdf)).pages).split())
    assert text.count("is in CISA's Known Exploited Vulnerabilities catalog") == 1
    assert "CVE-2025-6218 is in CISA's Known Exploited Vulnerabilities catalog (listed 2025-12-09" in text


def test_the_docx_report_marks_a_known_exploited_cve():
    import src.core.report_exporter as rx
    from docx import Document
    data = rx._export_vapt_docx("VAPT", [_finding([WINRAR])], [], "Completed",
                                metadata={"brand_firm": "Dhiware Technologies Pvt Ltd"})
    d = Document(io.BytesIO(data))
    text = " ".join(p.text for p in d.paragraphs)
    assert "Known exploited: CVE-2025-6218 is in CISA's Known Exploited Vulnerabilities catalog" in text


def test_the_card_badge_names_the_catalog_and_date_and_escapes_its_text():
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    app = io.open(os.path.join(os.path.dirname(KEV_PATH), "..", "..", "api", "static", "app.js"),
                  encoding="utf-8").read()

    def fn(name):
        start = app.index(f"function {name}(")
        depth, i = 0, app.index("{", start)
        while True:
            depth += app[i] == "{"
            depth -= app[i] == "}"
            i += 1
            if depth == 0:
                return app[start:i]
    k = {"cve": WINRAR, "date_added": "2025-12-09", "ransomware_use": "Unknown", "name": 'RAR "<x>" path'}
    script = fn("escapeHtml") + "\n" + fn("kevBadgeHtml") + "\nprocess.stdout.write(JSON.stringify(["
    script += "kevBadgeHtml(%s), kevBadgeHtml(null)]));" % json.dumps(k)
    html, empty = json.loads(subprocess.run([node, "-e", script], capture_output=True, text=True,
                                            timeout=30).stdout)
    assert "KNOWN EXPLOITED (CISA KEV, since 2025-12-09)" in html
    assert "<x>" not in html and "&lt;x&gt;" in html
    assert empty == ""
