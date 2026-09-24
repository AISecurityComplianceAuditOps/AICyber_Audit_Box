# -*- coding: utf-8 -*-
"""Every other output format the scanners write, read to the same findings.

Before these parsers, 25 of the 31 formats in tests/fixtures/scanner_formats.py
were wrong: 21 produced no findings at all (nikto CSV/XML/JSON, sqlmap's
results CSV, dirb, ffuf, feroxbuster, hydra JSON, medusa, nuclei, sslscan,
testssl.sh, enum4linux, masscan, Nessus CSV, ZAP XML, OpenVAS XML/CSV, the
Trivy table), WPScan JSON gave 2 of its 7 findings against automattic.com,
ZAP JSON gave three "Visual PoC" findings scraped from its text, and Qualys
scan XML rated everything INFO with a page of text as the target.

Each fixture carries the answer the tool itself gives; the content reaches
parse_tool_file exactly as the VAPT worker passes it (the file's bytes decoded).
"""
import importlib.util
import os

import pytest

from src.core.parsers import parse_tool_file

_spec = importlib.util.spec_from_file_location(
    "scanner_formats", os.path.join(os.path.dirname(__file__), "fixtures", "scanner_formats.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
FORMATS = _mod.S


def _parse(key):
    name, content, _exp = FORMATS[key]
    act, info = parse_tool_file(name, content, framework="vapt")
    return list(act) + (list(info) if isinstance(info, list) else [])


def _one(found, text):
    hits = [f for f in found if text.lower() in f.title.lower()]
    assert len(hits) == 1, f"expected one finding like {text!r}: {[f.title for f in found]}"
    return hits[0]


@pytest.mark.parametrize("key", sorted(FORMATS))
def test_format_is_read_to_the_tools_own_answer(key):
    found = _parse(key)
    exp = FORMATS[key][2]
    blob = lambda f: f"{f.title} {f.description} {f.evidence}".lower()
    assert len(found) >= exp.get("min", 0), [f.title for f in found]
    if "max" in exp:
        assert len(found) <= exp["max"], [f.title for f in found]
    for m in exp.get("mention", []):
        assert any(m.lower() in blob(f) for f in found), f"nothing mentions {m!r}"
    for sub, sev in exp.get("sev", {}).items():
        hits = [f for f in found if sub.lower() in f.title.lower()]
        assert hits and all(f.severity == sev for f in hits), (sub, [(f.title, f.severity) for f in hits])
    if exp.get("target"):
        assert all(exp["target"] in str(f.target) for f in found), [f.target for f in found]
    for n in exp.get("none", []):
        assert not any(n.lower() in f"{f.title} {f.evidence}".lower() for f in found), n


# ── Same scan, same findings, whatever the format ────────────────────────────

@pytest.mark.parametrize("key", ["nikto_csv", "nikto_xml", "nikto_json"])
def test_nikto_formats_rate_each_item_alike(key):
    # nikto 2.1 prefixes most lines with an OSVDB id and 2.5 prints none;
    # the rating must not depend on which one wrote the file.
    found = _parse(key)
    assert _one(found, "outdated").severity == "MEDIUM"
    assert _one(found, "X-Frame-Options").severity == "LOW"
    assert _one(found, "default file").severity == "LOW"
    assert _one(found, "phpMyAdmin").severity == "LOW"
    assert all(f.target == "shop.test (10.0.0.5):80" for f in found)


def test_directory_bruteforcers_agree():
    rated = {}
    for key in ("gobuster_outfile", "dirb", "ffuf_console", "feroxbuster"):
        rated[key] = {f.title: f.severity for f in _parse(key)}
    first = rated.pop("gobuster_outfile")
    for key, got in rated.items():
        assert got == first, key


# ── Tool-specific accuracy ───────────────────────────────────────────────────

def test_zap_is_read_by_its_own_parser_not_burp():
    for key in ("zap_xml", "zap_json"):
        found = _parse(key)
        assert {f.source_tool for f in found} == {"OWASP ZAP"}
        assert _one(found, "SQL Injection").cve_list == ["CWE-89"]


def test_openvas_results_are_labelled_openvas_not_qualys():
    for key in ("openvas_xml", "openvas_csv"):
        found = _parse(key)
        assert {f.source_tool for f in found} == {"OpenVAS"}
        cipher = _one(found, "Vulnerable Cipher Suites")
        assert cipher.cve_list == ["CVE-2016-2183", "CVE-2016-6329"]
        assert cipher.severity_score == 7.5


def test_openvas_log_result_is_informational():
    assert _one(_parse("openvas_xml"), "OS Detection").severity == "INFO"


def test_qualys_scan_xml_reads_attributes_and_host():
    f = _one(_parse("qualys_xml"), "Sweet32")
    assert f.severity == "MEDIUM"                       # Qualys level 3
    assert f.target == "10.0.0.5 / web01:443"
    assert f.severity_score == 7.5                      # CVSS3 before CVSS2
    assert f.cve_list == ["CVE-2016-2183"]


def test_nessus_csv_rows_are_one_finding_per_plugin_host_port():
    found = _parse("nessus_csv")
    sweet = _one(found, "SWEET32")
    assert sweet.target == "10.0.0.5:443/tcp" and sweet.severity_score == 7.5


def test_wpscan_json_target_is_the_site_not_the_banner_sponsor():
    found = _parse("wpscan_json")
    assert all(f.target == "http://blog.test/" for f in found)


def test_wordpress_core_vulnerability_is_fixed_by_a_core_update():
    f = _one(_parse("wpscan_json"), "Shortcode Previews")
    assert "wp core update" in f.remediation_actionable
    assert "plugin" not in f.remediation_actionable
    assert f.cve_list == ["CVE-2019-16219"]


def test_wordpress_plugin_vulnerability_names_the_plugin_update():
    f = _one(_parse("wpscan_json"), "Unrestricted File Upload")
    assert "Update Contact Form 7 to 5.3.2" in f.remediation_actionable
    assert "wp plugin update" in f.remediation_actionable
    assert f.category == "Vulnerable Components"


def test_nuclei_vendor_cve_fix_is_the_vendor_update_not_code_advice():
    f = _one(_parse("nuclei_jsonl"), "Path Traversal")
    assert f.severity == "CRITICAL" and f.severity_score == 7.5
    assert "2.4.51" in f.remediation_actionable
    assert "sanitize" not in f.remediation_actionable.lower()


def test_nuclei_template_without_remediation_gets_a_real_one():
    f = _one(_parse("nuclei_jsonl"), "Git Configuration")
    assert "Remove the exposed file" in f.remediation


def test_tls_findings_get_tls_steps_not_password_hashing():
    for key in ("testssl_csv", "testssl_json", "sslscan"):
        for f in _parse(key):
            assert f.category == "Cryptographic Failures", (key, f.title)
            assert "argon2" not in f.remediation_actionable.lower(), (key, f.title)
    beast = _one(_parse("testssl_csv"), "BEAST")
    assert "TLS 1.0" in beast.remediation_actionable


def test_sslscan_cipher_steps_are_about_ciphers():
    f = _one(_parse("sslscan"), "Weak Cipher Suites")
    assert "cipher" in f.remediation_actionable.lower()
    assert "RC4-SHA" in f.title and "DES-CBC3-SHA" in f.title


def test_brute_force_steps_do_not_tell_ssh_to_add_a_captcha():
    for key in ("hydra_json", "medusa", "hydra_outfile"):
        f = _parse(key)[0]
        assert "captcha" not in f.remediation_actionable.lower(), key
        assert "PasswordAuthentication no" in f.remediation_actionable, key
        assert "Summer2024!" not in f"{f.title} {f.description} {f.evidence}", key


def test_open_telnet_steps_say_ssh():
    f = _one(_parse("masscan"), "Telnet")
    assert "SSH" in f.remediation_actionable
    assert "FTPS" not in f.remediation_actionable


def test_trivy_package_cves_are_vulnerable_components():
    found = _parse("trivy_table")
    assert {f.category for f in found} == {"Vulnerable Components"}
    assert _one(found, "zlib").cve_list == ["CVE-2022-37434"]
    assert "1:1.2.11.dfsg-2+deb11u2" in _one(found, "zlib").remediation


def test_trivy_json_saved_without_json_extension_is_read():
    import json
    doc = json.dumps({"SchemaVersion": 2, "ArtifactName": "shop:1.0", "Results": [{
        "Target": "shop:1.0 (debian 11.6)", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2023-0286", "PkgName": "openssl", "InstalledVersion": "1.1.1n-0+deb11u3",
            "FixedVersion": "1.1.1n-0+deb11u4", "Severity": "HIGH", "Title": "openssl: X.400 address type confusion"}]}]})
    act, _info = parse_tool_file("trivy_report.txt", doc, framework="vapt")
    assert [f.cve_list for f in act] == [["CVE-2023-0286"]]


def test_sqlmap_run_that_found_nothing_reports_nothing():
    assert _parse("sqlmap_clean") == []
