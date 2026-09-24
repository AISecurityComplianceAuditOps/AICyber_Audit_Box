# -*- coding: utf-8 -*-
"""Each scanner export read field by field: what the tool reported is what the
finding says.

Every fixture is in the tool's own output format, and each test pins a defect
that published a wrong finding: a scanner's closing tally reported as a
vulnerability, every sqlmap finding filed against https://sqlmap.org, the home
page rated a MEDIUM exposure, a Burp HTML export that raised TypeError under
lxml, one weakness on 399 hosts reported once, a Qualys CSV read as empty.
"""
import pytest

from src.core.parsers import parse_tool_file
from src.core.parsers import burp_parser as burp_mod
from src.core.parsers.burp_parser import BurpParser
from src.core.parsers.kali_parser import KaliParser
from src.core.parsers.nmap_parser import NmapParser
from src.core.parsers.qualys_parser import QualysParser


def _all(result):
    act, info = result if isinstance(result, tuple) else (result, None)
    return list(act) + (list(info) if isinstance(info, list) else [])


def _one(findings, text):
    hits = [f for f in findings if text.lower() in f.title.lower()]
    assert len(hits) == 1, f"expected one finding titled like {text!r}, got {[f.title for f in findings]}"
    return hits[0]


# ── Kali tools ────────────────────────────────────────────────────────────────

NIKTO = """- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.0.0.5
+ Target Hostname:    shop.test
+ Target Port:        80
+ Start Time:         2025-06-24 10:00:00 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type.
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /phpmyadmin/: phpMyAdmin directory found.
+ 8102 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2025-06-24 10:05:00 (GMT0) (300 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
"""


def test_nikto_closing_tally_is_not_a_finding():
    found = _all(KaliParser().parse("nikto.txt", NIKTO))
    assert len(found) == 6, [f.title for f in found]
    assert not any("requests:" in f.title or "item(s) reported" in f.title for f in found)


def test_nikto_remediation_names_the_missing_header():
    found = _all(KaliParser().parse("nikto.txt", NIKTO))
    assert "nosniff" in _one(found, "X-Content-Type-Options").remediation
    assert "phpMyAdmin" in _one(found, "phpMyAdmin directory").remediation
    assert "default files" in _one(found, "default file").remediation


def test_nikto_note_about_its_own_false_positives_is_informational():
    act, info = KaliParser().parse("nikto.txt", NIKTO)
    assert any("junk HTTP methods" in f.title for f in info)
    assert not any("junk HTTP methods" in f.title for f in act)


SQLMAP = """        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[10:00:01] [INFO] testing connection to the target URL
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5102=5102
---
[10:00:05] [INFO] the back-end DBMS is MySQL
[10:00:05] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/shop.test'
"""


def test_sqlmap_target_is_the_host_tested_not_the_sqlmap_banner():
    found = _all(KaliParser().parse("sqlmap.txt", SQLMAP))
    assert found and all(f.target == "shop.test" for f in found), [f.target for f in found]


GOBUSTER = """===============================================================
Gobuster v3.6
===============================================================
[+] Url:                     http://shop.test
[+] Method:                  GET
===============================================================
/.git/HEAD            (Status: 200) [Size: 23]
/admin                (Status: 301) [Size: 312] [--> http://shop.test/admin/]
/backup               (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 10918]
/server-status        (Status: 403) [Size: 277]
===============================================================
"""


def test_gobuster_ordinary_page_is_informational_not_an_exposure():
    act, info = KaliParser().parse("gobuster.txt", GOBUSTER)
    assert [f.title for f in info] == ["Discovered path: /index.php (HTTP 200)"]
    assert info[0].severity == "INFO"
    assert "/index.php" not in " ".join(f.title for f in act)


def test_gobuster_sensitive_paths_rated_by_what_the_status_allows():
    act, _info = KaliParser().parse("gobuster.txt", GOBUSTER)
    assert _one(act, "/.git/HEAD").severity == "HIGH"          # readable
    assert _one(act, "/admin").severity == "MEDIUM"            # answering
    assert _one(act, "/backup").severity == "LOW"              # refused
    assert _one(act, "/server-status").severity == "LOW"


WPSCAN = """[+] URL: http://blog.test/ [10.0.0.7]

Interesting Finding(s):

[+] XML-RPC seems to be enabled: http://blog.test/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)

[+] WordPress readme found: http://blog.test/readme.html
 | Found By: Direct Access (Aggressive Detection)

[+] WordPress version 5.2.1 identified (Insecure, released on 2019-05-21).
 | Found By: Rss Generator (Passive Detection)

[+] WordPress theme in use: twentynineteen
 | Location: http://blog.test/wp-content/themes/twentynineteen/
 | [!] The version is out of date, the latest version is 2.5
 | Version: 1.4 (80% confidence)

[i] Plugin(s) Identified:

[+] contact-form-7
 | Location: http://blog.test/wp-content/plugins/contact-form-7/
 | [!] The version is out of date, the latest version is 5.9.5
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Contact Form 7 < 5.0.4 - Stored Cross Site Scripting in Admin Label
 |     Fixed in: 5.0.4
 |     References:
 |      - https://wpscan.com/vulnerability/00000000-0000-0000-0000-000000000000
 |
 | [!] Title: Contact Form 7 < 5.3.2 - Unrestricted File Upload
 |     Fixed in: 5.3.2
 |     References:
 |      - https://wpscan.com/vulnerability/7391118e-eef5-4ff8-a8ea-f6b65f442c63
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35489
 |
 | Version: 5.1.1 (80% confidence)

[+] Enumerating Users (via Passive and Aggressive Methods)
 User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)

[+] Finished: Tue Jun 24 10:01:00 2025
"""


def test_wpscan_reads_cve_from_its_reference_link():
    found = _all(KaliParser().parse("wpscan.txt", WPSCAN))
    upload = _one(found, "Unrestricted File Upload")
    assert upload.cve_list == ["CVE-2020-35489"]
    assert upload.severity == "HIGH"


def test_wpscan_cve_is_not_borrowed_by_the_vulnerability_before_it():
    found = _all(KaliParser().parse("wpscan.txt", WPSCAN))
    assert _one(found, "Stored Cross Site Scripting").cve_list == []


def test_wpscan_plugin_vulnerability_fix_is_the_vendor_update():
    found = _all(KaliParser().parse("wpscan.txt", WPSCAN))
    upload = _one(found, "Unrestricted File Upload")
    assert "Update Contact Form 7 to 5.3.2" in upload.remediation_actionable
    # The generic "file upload" template is about writing an upload handler.
    assert "magic bytes" not in upload.remediation_actionable


def test_wpscan_interesting_findings_are_read():
    found = _all(KaliParser().parse("wpscan.txt", WPSCAN))
    _one(found, "XML-RPC")
    assert _one(found, "readme").severity == "INFO"
    theme = _one(found, "Outdated WordPress theme")
    assert "twentynineteen 1.4" in theme.title and "2.5" in theme.title
    assert "5.9.5" in _one(found, "Outdated WordPress plugin").title
    assert _one(found, "user enumeration").title.endswith("admin")


# ── Nmap ──────────────────────────────────────────────────────────────────────

NMAP_TWO_HOSTS = """# Nmap 7.92 scan initiated Mon Jun 23 10:00:00 2025 as: nmap -sV --script ssl-enum-ciphers,ssl-cert,ssl-date 10.0.0.4/30
Nmap scan report for web01 (10.0.0.5)
Host is up (0.0010s latency).
PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.3.4 (Backdoor CVE-2011-2523)
23/tcp  open  telnet   Linux telnetd
443/tcp open  ssl/http Apache httpd 2.4.29
| ssl-cert: Subject: commonName=web01
| Not valid before: 2020-01-01T00:00:00
|_Not valid after:  2024-01-01T00:00:00
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - Vulnerable to LUCKY13 (CVE-2013-0169)
|       TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - Vulnerable to LUCKY13 (CVE-2013-0169)
|_  least strength: C

Nmap scan report for web02 (10.0.0.6)
Host is up (0.0010s latency).
PORT    STATE SERVICE VERSION
23/tcp  open  telnet  Linux telnetd
443/tcp open  https
|_ssl-date: TLSv1.0 (WEAK PROTOCOL DETECTED - PCI-DSS NON-COMPLIANT)
| ssl-cert: Subject: commonName=web02
|_Not valid after:  2026-01-01T00:00:00

# Nmap done at Mon Jun 23 10:05:00 2025 -- 4 IP addresses (2 hosts up) scanned in 300.00 seconds
"""


def _nmap(text, name="scan.txt"):
    return NmapParser().parse(name, text)[0]


def _on(findings, target):
    return [f for f in findings if f.target == target]


def test_nmap_same_weakness_on_two_hosts_is_two_findings():
    found = _nmap(NMAP_TWO_HOSTS)
    telnet = [f for f in found if "Telnet" in f.title]
    assert sorted(f.target for f in telnet) == ["web01 (10.0.0.5)", "web02 (10.0.0.6)"]
    assert all(f.severity == "HIGH" for f in telnet)


def test_nmap_cve_in_the_version_column_is_read():
    found = _on(_nmap(NMAP_TWO_HOSTS), "web01 (10.0.0.5)")
    backdoor = [f for f in found if "CVE-2011-2523" in f.cve_list]
    assert len(backdoor) == 1 and backdoor[0].severity == "CRITICAL"
    assert "(21/tcp)" in backdoor[0].title


def test_nmap_one_cve_across_several_ciphers_is_one_finding_naming_them():
    found = _on(_nmap(NMAP_TWO_HOSTS), "web01 (10.0.0.5)")
    lucky = [f for f in found if "CVE-2013-0169" in f.cve_list]
    assert len(lucky) == 1, [f.title for f in lucky]
    assert "TLS_RSA_WITH_AES_128_CBC_SHA" in lucky[0].title
    assert "TLS_RSA_WITH_AES_256_CBC_SHA" in lucky[0].title
    assert lucky[0].evidence.count("LUCKY13") == 2


def test_nmap_weak_cipher_suite_is_a_finding():
    found = _on(_nmap(NMAP_TWO_HOSTS), "web01 (10.0.0.5)")
    weak = [f for f in found if "Weak Cipher Suites" in f.title]
    assert len(weak) == 1 and "3DES" in weak[0].evidence


def test_nmap_one_weak_protocol_line_is_one_finding():
    found = _on(_nmap(NMAP_TWO_HOSTS), "web02 (10.0.0.6)")
    proto = [f for f in found if "Protocol" in f.title]
    assert [f.title for f in proto] == ["Nmap: Weak SSL/TLS Protocol Supported (443/tcp)"]


def test_nmap_certificate_expiry_judged_against_the_scan_date():
    found = _nmap(NMAP_TWO_HOSTS)
    expired = [f for f in found if "Certificate Expired" in f.title]
    # web01 expired 2024-01-01, before the 2025-06-23 scan; web02's runs to 2026.
    assert [f.target for f in expired] == ["web01 (10.0.0.5)"]


def test_nmap_numbered_report_header_names_the_host():
    text = ("# Nmap 7.92 scan report for 192.168.1.10\n"
            "PORT   STATE SERVICE\n"
            "23/tcp open  telnet\n")
    found = _nmap(text)
    assert found and all(f.target == "192.168.1.10" for f in found), [f.target for f in found]


NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV --script ssl-enum-ciphers -oX scan.xml 10.0.0.5-6">
<host><address addr="10.0.0.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="Linux telnetd"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/>
<script id="ssl-enum-ciphers" output="TLSv1.0: ciphers: TLS_RSA_WITH_3DES_EDE_CBC_SHA - C"/></port>
</ports></host>
<host><address addr="10.0.0.6" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/>
<script id="ssl-enum-ciphers" output="TLSv1.0: ciphers: TLS_RSA_WITH_3DES_EDE_CBC_SHA - C"/></port>
</ports></host>
</nmaprun>
"""


def test_nmap_xml_identical_script_output_on_two_hosts_is_kept_for_both():
    found = _nmap(NMAP_XML, "scan.xml")
    weak = [f for f in found if "Weak Cipher Suites" in f.title]
    assert sorted(f.target for f in weak) == ["10.0.0.5", "10.0.0.6"]


def test_nmap_xml_open_telnet_is_a_finding():
    found = _nmap(NMAP_XML, "scan.xml")
    telnet = [f for f in found if "Telnet" in f.title]
    assert len(telnet) == 1 and telnet[0].target == "10.0.0.5" and telnet[0].severity == "HIGH"


def test_nmap_grepable_open_telnet_is_a_finding():
    text = ("# Nmap 7.92 scan initiated as: nmap -oG scan.gnmap 10.0.0.9\n"
            "Host: 10.0.0.9 (h9)\tStatus: Up\n"
            "Host: 10.0.0.9 (h9)\tPorts: 22/open/tcp//ssh//OpenSSH 8.9/, 23/open/tcp//telnet///\t"
            "Ignored State: closed (998)\n")
    found = _nmap(text, "scan.gnmap")
    telnet = [f for f in found if "Telnet" in f.title]
    assert len(telnet) == 1 and telnet[0].target == "h9 (10.0.0.9)"


# ── Qualys ────────────────────────────────────────────────────────────────────

QUALYS = '''"Scan Results","Scan Results"
"Launch Date","06/24/2025 10:00:00"
"Active Hosts","2"

"IP","DNS","OS","QID","Title","Type","Severity","Port","Protocol","CVE ID","CVSS Base","CVSS3.1 Base","Threat","Impact","Solution","Results"
"10.0.0.5","web01","Ubuntu 18.04","38657","Birthday attacks against TLS ciphers with 64bit block size vulnerability (Sweet32)","Vuln","3","443","tcp","CVE-2016-2183","5.0","7.5","Legacy 64-bit block ciphers are vulnerable to collision attacks.","A MITM attacker could recover plaintext.","Disable ciphers with a 64 bit block size.","DES-CBC3-SHA"
"10.0.0.5","web01","Ubuntu 18.04","86473","Web Server HTTP Trace/Track Method Support Cross-Site Tracing Vulnerability","Vuln","2","80","tcp","","5.8","5.3","The TRACE method is enabled.","Cross-site tracing.","Disable the TRACE method.","TRACE / HTTP/1.1"
"10.0.0.5","web01","Ubuntu 18.04","82023","Open TCP Services List","Ig","1","","","","","","The host has open TCP services.","","","22, 80, 443"
'''


def test_qualys_report_with_metadata_block_is_read():
    found = QualysParser().parse("qualys_scan.csv", QUALYS)
    found = _all(found)
    assert len(found) == 3, [f.title for f in found]


def test_qualys_cvss3_preferred_over_cvss2():
    found = _all(QualysParser().parse("qualys_scan.csv", QUALYS))
    assert _one(found, "Sweet32").severity_score == 7.5
    assert _one(found, "Trace/Track").severity_score == 5.3


def test_qualys_information_gathered_row_is_informational():
    found = _all(QualysParser().parse("qualys_scan.csv", QUALYS))
    assert _one(found, "Open TCP Services").severity == "INFO"
    assert _one(found, "Sweet32").severity != "INFO"


# ── Burp HTML ─────────────────────────────────────────────────────────────────

BURP_HTML = """<html><head><title>Burp Scanner Report</title></head><body>
<p class="TOCH0"><a href="https://portswigger.net/burp/samplereport#1">1. SQL injection</a></p>
<p class="TOCH0"><a href="https://portswigger.net/burp/samplereport#2">2. Cookie without HttpOnly flag set</a></p>
<br><div class="rule"></div>
<span class="BODH0" id="1">1.&nbsp;<a href="https://portswigger.net/kb/sqli">SQL injection</a></span>
<br><a class="PREVNEXT" href="#2">Next</a>
<h2>Issue background</h2>
<span class="TEXT">SQL injection vulnerabilities arise when user-controllable data is incorporated into SQL queries unsafely.</span>
<h2>Issue remediation</h2>
<span class="TEXT">Use parameterized queries for all database access.</span>
<h2>Vulnerability classifications</h2><span class="TEXT"><ul>
<li><a href="https://cwe.mitre.org/data/definitions/89.html">CWE-89: SQL Injection</a></li>
</ul></span>
<br><div class="rule"></div>
<span class="BODH1" id="1.1">1.1.&nbsp;https://shop.test/catalog/filter [category parameter]</span>
<h2>Summary</h2>
<table class="summary_table"><tbody>
<tr><td>Severity:&nbsp;&nbsp;</td><td><b>High</b></td></tr>
<tr><td>Confidence:&nbsp;&nbsp;</td><td><b>Certain</b></td></tr>
<tr><td>Host:&nbsp;&nbsp;</td><td><b>https://shop.test</b></td></tr>
<tr><td>Path:&nbsp;&nbsp;</td><td><b>/catalog/filter</b></td></tr>
</tbody></table>
<h2>Issue detail</h2>
<span class="TEXT">The category parameter appears to be vulnerable to SQL injection attacks.</span>
<h2>Remediation detail</h2>
<span class="TEXT">Parameterise the category filter query.</span>
<br><div class="rule"></div>
<span class="BODH0" id="2">2.&nbsp;<a href="https://portswigger.net/kb/httponly">Cookie without HttpOnly flag set</a></span>
<h2>Issue background</h2>
<span class="TEXT">If the HttpOnly attribute is set on a cookie, client-side JavaScript cannot read it.</span>
<h2>Issue remediation</h2>
<span class="TEXT">Set the HttpOnly flag on session cookies.</span>
<h2>Vulnerability classifications</h2><span class="TEXT"><ul>
<li><a href="https://cwe.mitre.org/data/definitions/16.html">CWE-16: Configuration</a></li>
<li><a href="https://cwe.mitre.org/data/definitions/1004.html">CWE-1004: Sensitive Cookie Without HttpOnly Flag</a></li>
</ul></span>
<br><div class="rule"></div>
<span class="BODH1" id="2.1">2.1.&nbsp;https://shop.test/</span>
<h2>Summary</h2>
<table class="summary_table"><tbody>
<tr><td>Severity:&nbsp;&nbsp;</td><td><b>Low</b></td></tr>
<tr><td>Confidence:&nbsp;&nbsp;</td><td><b>Firm</b></td></tr>
<tr><td>Host:&nbsp;&nbsp;</td><td><b>https://shop.test</b></td></tr>
<tr><td>Path:&nbsp;&nbsp;</td><td><b>/</b></td></tr>
</tbody></table>
<h2>Issue detail</h2>
<span class="TEXT">The following cookie was issued without the HttpOnly flag: session</span>
</body></html>
"""


@pytest.fixture(params=["lxml", "html.parser"])
def html_parser(request, monkeypatch):
    if request.param == "lxml":
        pytest.importorskip("lxml")
    monkeypatch.setattr(burp_mod, "_HTML_PARSER", request.param)
    return request.param


def _burp_html():
    act, info = BurpParser()._parse_html(BURP_HTML)
    return list(act) + list(info)


def test_burp_html_export_parses_under_either_html_parser(html_parser):
    found = _burp_html()
    assert len(found) == 2, [f.title for f in found]


def test_burp_html_keeps_the_reports_severity(html_parser):
    found = _burp_html()
    sqli = _one(found, "SQL injection")
    assert sqli.severity == "HIGH"
    assert 7.0 <= float(sqli.severity_score) < 9.0
    cookie = _one(found, "HttpOnly")
    assert cookie.severity == "LOW"
    assert 0.0 < float(cookie.severity_score) < 4.0


def test_burp_html_cwes_belong_to_their_own_issue(html_parser):
    found = _burp_html()
    assert _one(found, "SQL injection").cve_list == ["CWE-89"]
    assert _one(found, "HttpOnly").cve_list == ["CWE-16", "CWE-1004"]


def test_burp_html_dispatch_reaches_the_html_path():
    act, info = parse_tool_file("burp_report.html", BURP_HTML, framework="vapt")
    titles = [f.title for f in list(act) + list(info or [])]
    assert any("SQL injection" in t for t in titles), titles
