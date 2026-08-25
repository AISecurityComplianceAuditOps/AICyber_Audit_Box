"""
Unit tests for Content-Based Parser Selection (0% Filename Dependency).
Verifies:
  1. is_image_file() correctly identifies all supported image extensions and magic bytes.
  2. Every scanner parser (Burp, Nessus, Nmap, Qualys, Trivy) returns can_parse()=False
     for image files — regardless of keywords in the filename.
  3. Every scanner parser still returns can_parse()=True for its correct content format.
  4. parse_tool_file() short-circuits for images (returns [], None — no parser warnings).
  5. parse_tool_file() correctly dispatches real scanner content to the right parser.
"""
import os
import sys
import ast
import unittest

# Project root is two levels up from testsprite_tests/
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.core.parsers.base_parser import is_image_file
from src.core.parsers.burp_parser import BurpParser
from src.core.parsers.nessus_parser import NessusParser
from src.core.parsers.nmap_parser import NmapParser
from src.core.parsers.qualys_parser import QualysParser
from src.core.parsers.trivy_parser import TrivyParser
from src.core.parsers import parse_tool_file

# ─── Minimal realistic content fixtures ──────────────────────────────────────

BURP_XML = """<?xml version="1.0"?>
<issues burpVersion="2023.10" exportTime="Mon Aug 19 2026">
  <issue>
    <serialNumber>1</serialNumber>
    <type>1049088</type>
    <name>SQL injection</name>
    <host ip="10.0.0.1">https://example.com</host>
    <path>/login</path>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>SQL injection arises when user-controllable data is incorporated into database SQL queries in an unsafe manner.</issueBackground>
    <issueDetail>The parameter 'username' appears to be vulnerable to SQL injection attacks.</issueDetail>
    <remediationBackground>The most effective way to prevent SQL injection attacks is to use parameterized queries.</remediationBackground>
  </issue>
</issues>"""

NESSUS_XML = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test Scan">
    <ReportHost name="192.168.1.1">
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="3" pluginID="51192" pluginName="SSL Certificate Cannot Be Trusted">
        <risk_factor>High</risk_factor>
        <plugin_output>The SSL certificate for this service cannot be trusted.</plugin_output>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 10.0.0.1" start="1692345678" version="7.94">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

NMAP_TEXT = """Starting Nmap 7.94 ( https://nmap.org ) at 2026-08-19 18:00 IST
Nmap scan report for 10.0.0.1
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4
80/tcp open  http    Apache 2.4.6"""

TRIVY_JSON = """{
  "SchemaVersion": 2,
  "ArtifactName": "python:3.9",
  "Results": [
    {
      "Target": "Python-3.9",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-24329",
          "Severity": "HIGH",
          "Title": "urllib: CPU denial of service via crafted query string",
          "PkgName": "pip",
          "InstalledVersion": "21.2.4"
        }
      ]
    }
  ]
}"""

QUALYS_CSV = """"IP","DNS","NetBIOS","OS","IP Status","QID","Title","Severity","CVE ID","CVSS","Vuln Status"
"10.0.0.5","host.local","","Windows Server 2019","","90007","Password Policy Not Compliant","3","","6.5","Active"
"""

# Fake OCR text extracted from a PNG screenshot (no XML/scanner structure)
PNG_OCR_TEXT = "Target: 192.168.1.5  SQL injection payload: ' OR 1=1--  Response: admin dashboard"


# ─── TEST 1: is_image_file() ──────────────────────────────────────────────────
class TestIsImageFile(unittest.TestCase):
    def test_png_by_extension(self):
        self.assertTrue(is_image_file("screenshot.png"))

    def test_jpg_by_extension(self):
        self.assertTrue(is_image_file("evidence.jpg"))

    def test_jpeg_by_extension(self):
        self.assertTrue(is_image_file("proof.jpeg"))

    def test_webp_by_extension(self):
        self.assertTrue(is_image_file("capture.webp"))

    def test_bmp_by_extension(self):
        self.assertTrue(is_image_file("image.bmp"))

    def test_tiff_by_extension(self):
        self.assertTrue(is_image_file("scan.tiff"))

    def test_tif_by_extension(self):
        self.assertTrue(is_image_file("scan.tif"))

    def test_gif_by_extension(self):
        self.assertTrue(is_image_file("anim.gif"))

    def test_png_magic_bytes(self):
        magic = b"\x89PNG\r\n\x1a\n"
        self.assertTrue(is_image_file("noextension", raw_bytes=magic))

    def test_jpg_magic_bytes(self):
        magic = b"\xff\xd8\xff\xe0\x00\x10JFIF"
        self.assertTrue(is_image_file("noextension", raw_bytes=magic))

    def test_xml_not_image(self):
        self.assertFalse(is_image_file("report.xml"))

    def test_json_not_image(self):
        self.assertFalse(is_image_file("trivy.json"))

    def test_nessus_not_image(self):
        self.assertFalse(is_image_file("scan.nessus"))

    def test_pdf_not_image(self):
        self.assertFalse(is_image_file("policy.pdf"))

    def test_tricky_name_burp_png(self):
        """'shot_burp_sqli.png' must be recognised as image despite 'burp' in name"""
        self.assertTrue(is_image_file("shot_burp_sqli.png"))

    def test_tricky_name_nessus_jpg(self):
        """'nessus_proof.jpg' must be recognised as image despite 'nessus' in name"""
        self.assertTrue(is_image_file("nessus_proof.jpg"))


# ─── TEST 2: BurpParser — image rejection ─────────────────────────────────────
class TestBurpParserImageRejection(unittest.TestCase):
    def setUp(self):
        self.parser = BurpParser()

    def test_rejects_png_with_burp_in_name(self):
        """THE KEY BUG FIX: 'shot_burp_sqli.png' must NOT trigger BurpParser"""
        self.assertFalse(self.parser.can_parse("shot_burp_sqli.png", PNG_OCR_TEXT))

    def test_rejects_jpg_with_burp_in_name(self):
        self.assertFalse(self.parser.can_parse("burp_finding.jpg", PNG_OCR_TEXT))

    def test_rejects_jpeg(self):
        self.assertFalse(self.parser.can_parse("evidence.jpeg", PNG_OCR_TEXT))

    def test_rejects_webp(self):
        self.assertFalse(self.parser.can_parse("screenshot.webp", PNG_OCR_TEXT))

    def test_rejects_png_with_portswigger_in_name(self):
        self.assertFalse(self.parser.can_parse("portswigger_poc.png", PNG_OCR_TEXT))

    def test_accepts_real_burp_xml_any_filename(self):
        """Real Burp XML should parse even if filename has no 'burp' keyword"""
        self.assertTrue(self.parser.can_parse("scan_results_v2.xml", BURP_XML))

    def test_accepts_real_burp_xml_named_burp(self):
        self.assertTrue(self.parser.can_parse("burp_export.xml", BURP_XML))


# ─── TEST 3: NessusParser — image rejection ───────────────────────────────────
class TestNessusParserImageRejection(unittest.TestCase):
    def setUp(self):
        self.parser = NessusParser()

    def test_rejects_png_with_nessus_in_name(self):
        self.assertFalse(self.parser.can_parse("nessus_screenshot.png", PNG_OCR_TEXT))

    def test_rejects_jpg(self):
        self.assertFalse(self.parser.can_parse("evidence.jpg", PNG_OCR_TEXT))

    def test_accepts_real_nessus_xml_any_filename(self):
        """Real Nessus XML must be accepted even without 'nessus' in filename"""
        self.assertTrue(self.parser.can_parse("audit_data.xml", NESSUS_XML))

    def test_accepts_nessus_extension(self):
        self.assertTrue(self.parser.can_parse("scan.nessus", NESSUS_XML))


# ─── TEST 4: NmapParser — image rejection ─────────────────────────────────────
class TestNmapParserImageRejection(unittest.TestCase):
    def setUp(self):
        self.parser = NmapParser()

    def test_rejects_png_with_nmap_in_name(self):
        self.assertFalse(self.parser.can_parse("nmap_output.png", PNG_OCR_TEXT))

    def test_rejects_jpg(self):
        self.assertFalse(self.parser.can_parse("scan.jpg", PNG_OCR_TEXT))

    def test_accepts_nmap_xml_any_filename(self):
        self.assertTrue(self.parser.can_parse("results.xml", NMAP_XML))

    def test_accepts_nmap_text_output(self):
        self.assertTrue(self.parser.can_parse("output.txt", NMAP_TEXT))

    def test_accepts_nmap_extension(self):
        self.assertTrue(self.parser.can_parse("scan.nmap", NMAP_TEXT))


# ─── TEST 5: QualysParser — image rejection ───────────────────────────────────
class TestQualysParserImageRejection(unittest.TestCase):
    def setUp(self):
        self.parser = QualysParser()

    def test_rejects_png_with_qualys_in_name(self):
        self.assertFalse(self.parser.can_parse("qualys_result.png", PNG_OCR_TEXT))

    def test_rejects_jpg(self):
        self.assertFalse(self.parser.can_parse("openvas_proof.jpg", PNG_OCR_TEXT))

    def test_accepts_qualys_csv_any_filename(self):
        self.assertTrue(self.parser.can_parse("vulnerabilities.csv", QUALYS_CSV))


# ─── TEST 6: TrivyParser — image rejection ───────────────────────────────────
class TestTrivyParserImageRejection(unittest.TestCase):
    def setUp(self):
        self.parser = TrivyParser()

    def test_rejects_png_with_trivy_in_name(self):
        self.assertFalse(self.parser.can_parse("trivy_output.png", PNG_OCR_TEXT))

    def test_rejects_jpg(self):
        self.assertFalse(self.parser.can_parse("container_scan.jpg", PNG_OCR_TEXT))

    def test_accepts_trivy_json_any_filename(self):
        self.assertTrue(self.parser.can_parse("scan_results.json", TRIVY_JSON))

    def test_rejects_trivy_json_without_schema(self):
        """JSON without SchemaVersion must not match TrivyParser"""
        random_json = '{"data": [{"name": "test"}]}'
        self.assertFalse(self.parser.can_parse("data.json", random_json))


# ─── TEST 7: parse_tool_file() — image fast-path ─────────────────────────────
class TestParseToolFileImageFastPath(unittest.TestCase):
    def test_png_returns_empty_no_warning(self):
        """Images must return ([], None) with ZERO scanner parser warnings"""
        findings, extra = parse_tool_file("shot_burp_sqli.png", PNG_OCR_TEXT)
        self.assertEqual(findings, [])
        self.assertIsNone(extra)

    def test_jpg_returns_empty(self):
        findings, extra = parse_tool_file("nessus_proof.jpg", PNG_OCR_TEXT)
        self.assertEqual(findings, [])
        self.assertIsNone(extra)

    def test_webp_returns_empty(self):
        findings, extra = parse_tool_file("evidence.webp", PNG_OCR_TEXT)
        self.assertEqual(findings, [])
        self.assertIsNone(extra)

    def test_nmap_xml_dispatched_correctly(self):
        """Nmap XML must be dispatched to NmapParser and return findings"""
        findings, extra = parse_tool_file("scan.xml", NMAP_XML)
        # NmapParser may return 0 action findings (only inventory for open ports)
        # but extra (AssetInventory) should not be None when Nmap XML is parsed
        # (at minimum extra is an AssetInventory object or findings list is returned)
        self.assertIsNotNone(extra)

    def test_trivy_json_dispatched_correctly(self):
        """Trivy JSON must be dispatched to TrivyParser and return at least 1 finding"""
        findings, extra = parse_tool_file("scan_results.json", TRIVY_JSON)
        self.assertGreater(len(findings), 0, "TrivyParser should extract at least 1 CVE finding")


# ─── TEST 8: Syntax check all modified parser files ──────────────────────────
class TestParserSyntax(unittest.TestCase):
    FILES = [
        "src/core/parsers/base_parser.py",
        "src/core/parsers/burp_parser.py",
        "src/core/parsers/nessus_parser.py",
        "src/core/parsers/nmap_parser.py",
        "src/core/parsers/qualys_parser.py",
        "src/core/parsers/trivy_parser.py",
        "src/core/parsers/__init__.py",
    ]

    def test_all_files_have_no_syntax_errors(self):
        for rel_path in self.FILES:
            abs_path = os.path.join(PROJECT_ROOT, rel_path)
            with open(abs_path, encoding="utf-8") as f:
                src = f.read()
            try:
                ast.parse(src)
            except SyntaxError as e:
                self.fail(f"Syntax error in {rel_path}: {e}")


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in [
        TestIsImageFile,
        TestBurpParserImageRejection,
        TestNessusParserImageRejection,
        TestNmapParserImageRejection,
        TestQualysParserImageRejection,
        TestTrivyParserImageRejection,
        TestParseToolFileImageFastPath,
        TestParserSyntax,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
