"""Remediation for a finding whose source gave none: MITRE CWE's mitigations.

A pentest report's findings table often has no remediation column, and the
report then printed a template written in this codebase. The knowledge file
src/core/knowledge/cwe_mitigations.json, built from MITRE's CWE list by
scripts/build_cwe_mitigations.py, supplies MITRE's own mitigations for the
finding's weakness instead -- labelled as general guidance, never as the
tester's advice. A finding with a CVE gets the vendor's patch; a finding whose
source did give remediation is untouched.
"""
import io
import json
import os
import re
import shutil
import subprocess

import pytest

from src.core.parsers import control_mapper as cm
from src.core.parsers.finding_schema import Finding

KB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "src", "core", "knowledge", "cwe_mitigations.json")


def _f(title, cves=(), remediation=""):
    return Finding(title=title, severity="MEDIUM", cve_list=list(cves), target="https://portal.test/",
                   description="", remediation=remediation, evidence="", source_tool="Pentest Report")


def test_the_knowledge_file_carries_mitres_notice_and_version():
    kb = json.load(io.open(KB_PATH, encoding="utf-8"))
    assert kb["version"] and kb["date"]
    assert "The MITRE Corporation" in kb["notice"] and "reproduce MITRE's copyright designation" in kb["notice"]
    assert len(kb["cwe"]) > 500


def test_a_finding_with_its_own_cwe_and_no_remediation_gets_mitres_mitigations():
    text = cm.get_actionable_remediation(_f("Cleartext Transmission of Phone Numbers", ["CWE-319"]))
    assert text.startswith("General guidance from MITRE CWE-319 (Cleartext Transmission of Sensitive "
                           "Information), not from the report: 1. ")
    assert "Before transmitting, encrypt the data using reliable, confidentiality-protecting" in text
    assert "hardware" not in text.lower()               # hardware-only advice left out
    assert "OWASP Transport Layer Security Cheat Sheet (https://cheatsheetseries.owasp.org/" in text


def test_a_finding_whose_source_gave_remediation_is_untouched():
    text = cm.get_actionable_remediation(_f("Cleartext Transmission", ["CWE-319"],
                                            remediation="Enable TLS on port 9007."))
    assert "MITRE" not in text


def test_a_cve_is_fixed_by_the_vendors_patch_not_by_code_advice():
    """"Sanitize file path inputs" was the advice for WinRAR's CVE-2025-6218."""
    text = cm.get_actionable_remediation(
        _f("RARLAB WinRAR < 7.12 Beta 1 Directory Traversal (CVE-2025-6218)", ["CVE-2025-6218"]))
    # (WinRAR's CVE is also in CISA's KEV catalog, whose note comes first; see
    # tests/test_cisa_kev.py.)
    assert "Apply the vendor-supplied patch addressing CVE-2025-6218" in text
    assert "MITRE" not in text and "Sanitize" not in text


@pytest.mark.parametrize("title,cwe", [
    ("SQL injection", "CWE-89"),
    ("Cross-site scripting (reflected)", "CWE-79"),
    ("XML external entity injection", "CWE-611"),
    ("Open redirection (DOM-based)", "CWE-601"),
    ("Strict transport security not enforced", "CWE-523"),
    ("Cookie without HttpOnly flag set", "CWE-1004"),
    ("Clear Text Data Transmission", "CWE-319"),
])
def test_a_title_names_its_weakness_when_the_finding_has_no_cwe(title, cwe):
    assert cm.get_actionable_remediation(_f(title)).startswith(f"General guidance from MITRE {cwe} (")


def test_a_title_that_only_mentions_plaintext_is_not_cleartext_transmission():
    assert "CWE-319" not in cm.get_actionable_remediation(_f("Processes reveal plaintext passwords"))


def test_a_class_too_broad_to_guide_a_fix_is_skipped_for_a_specific_one():
    """Burp gives "Input returned in response" CWE-20 and CWE-116; CWE-20's
    first mitigation is "consider language-theoretic security"."""
    text = cm.get_actionable_remediation(_f("Input returned in response (reflected)", ["CWE-20", "CWE-116"]))
    assert text.startswith("General guidance from MITRE CWE-116 (")


def test_every_title_mapping_names_a_weakness_mitre_has_mitigations_for():
    kb = json.load(io.open(KB_PATH, encoding="utf-8"))["cwe"]
    absent = [c for _p, c in cm._TITLE_TO_CWE if c not in kb]
    # CWE-918 (SSRF) has no mitigations in CWE 4.20; it keeps the written template.
    assert set(absent) <= {"CWE-918"}, absent


def test_mitres_citation_markers_never_reach_a_report():
    kb = json.load(io.open(KB_PATH, encoding="utf-8"))["cwe"]
    for cwe, entry in kb.items():
        for step in cm._pick_mitigations(entry["mitigations"]):
            assert not re.search(r"\[REF-|According to,|\(\s*\)", step), (cwe, step[:80])


def test_the_card_lists_mitres_steps_under_their_label():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    app = io.open(os.path.join(os.path.dirname(KB_PATH), "..", "..", "api", "static", "app.js"),
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
    text = cm.get_actionable_remediation(_f("Cleartext Transmission of Phone Numbers", ["CWE-319"]))
    script = "\n".join(fn(n) for n in ("escapeHtml", "splitSentences", "remediationPoints",
                                        "formatRemediationSteps"))
    script += "\nprocess.stdout.write(formatRemediationSteps(%s, '#123'));" % json.dumps(text)
    html = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30).stdout
    assert html.count("<li") == 3
    assert "not from the report:</p>" in html
