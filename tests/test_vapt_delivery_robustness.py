# -*- coding: utf-8 -*-
"""A scan gives the same findings however the auditor delivers it, and a file
with no vulnerability in it gives none.

Found by running every verified sample through the real VAPT worker in every
form an auditor uses. Before these fixes:

  * UTF-16 (PowerShell ">" / Out-File) lost every finding of every tool;
  * a UTF-8 byte-order mark (Excel, Notepad) lost them for 17 formats, and made
    ZAP and OpenVAS reports produce junk instead;
  * a .zip of .xml / .json / .nessus exports lost all of them;
  * a CSV export saved as .xlsx lost all of them;
  * several tools' output pasted into one .txt kept only the first tool's;
  * the same Nessus scan uploaded as .nessus and .csv listed every finding twice;
  * a WAF summary, a methodology note, a secure-coding policy and a letter
    confirming an SQL injection FIXED each became a HIGH "Visual PoC: SQL
    Injection"; a change record reading "Risk: Low" a LOW "VAPT Finding";
  * a screenshot of "Nightly database backup completed" became a HIGH "SQL
    Injection Detected";
  * code / dependency scanner exports (SARIF, Grype, npm audit, gitleaks,
    Bandit, a CI pipeline's findings JSON) were read by nothing.
"""
import csv
import importlib.util
import io
import json
import os
import zipfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import src.core.bg_worker as worker
from src.core.parsers import parse_tool_file
from src.db.database import AuditReport, Base, Finding

HERE = os.path.dirname(os.path.abspath(__file__))
NESSUS = os.path.join(HERE, "fixtures", "two_host_findings.nessus")


def _fixture_module(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, "fixtures", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SCANNERS = _fixture_module("scanner_formats").S
CODE = _fixture_module("code_scan_formats").C


@pytest.fixture
def run(tmp_path, monkeypatch):
    eng = create_engine("sqlite:///" + str(tmp_path / "vapt.db"))
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    monkeypatch.setattr(worker, "SessionLocal", S)
    counter = {"n": 0}

    def _run(files, **kw):
        counter["n"] += 1
        sid = f"s{counter['n']}"
        s = S()
        s.add(AuditReport(session_id=sid, session_title=sid, framework="VAPT"))
        s.commit()
        s.close()
        worker._run_fast_technical_vapt_bg(sid, [{"name": n, "bytes": b, "text": None} for n, b in files],
                                           selected_sls=[], framework="VAPT", **kw)
        s = S()
        try:
            rep = s.query(AuditReport).filter(AuditReport.session_id == sid).first()
            return sorted((r.control_name or "", r.severity or "", r.target or "")
                          for r in s.query(Finding).filter(Finding.report_id == rep.id))
        finally:
            s.close()
    return _run


def _nessus():
    return io.open(NESSUS, "rb").read()


# ── encodings ────────────────────────────────────────────────────────────────

def test_a_utf16_file_from_powershell_reads_like_the_original(run):
    plain = run([("scan.nessus", _nessus())])
    assert plain
    assert run([("scan.nessus", _nessus().decode("utf-8").encode("utf-16"))]) == plain
    assert run([("scan.nessus", _nessus().decode("utf-8").encode("utf-16-le"))]) == plain   # no BOM


def test_a_byte_order_mark_hides_nothing(run):
    for key in ("zap_json", "nikto_json", "testssl_csv", "wpscan_json"):
        name, content, _exp = SCANNERS[key]
        assert run([(name, b"\xef\xbb\xbf" + content.encode())]) == run([(name, content.encode())]), key


def test_decoder_handles_each_encoding():
    text = "Nmap scan report for web01 — ok"
    for enc in ("utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32"):
        assert worker._decode_scan_bytes(text.encode(enc)) == text, enc
    assert worker._decode_scan_bytes("café résumé".encode("cp1252")) == "café résumé"


# ── containers ───────────────────────────────────────────────────────────────

def _zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


def test_a_zip_of_exports_reads_every_member_with_its_own_parser(run):
    nikto_name, nikto, _e = SCANNERS["nikto_xml"]
    each = run([("scan.nessus", _nessus())]) + run([(nikto_name, nikto.encode())])
    zipped = run([("results.zip", _zip([("exports/scan.nessus", _nessus()),
                                        ("exports/" + nikto_name, nikto.encode()),
                                        ("tools/helper.exe", b"MZ\x90\x00binary")]))])
    assert zipped == sorted(each)


def test_a_csv_export_saved_as_xlsx_reads_like_the_csv(run):
    openpyxl = pytest.importorskip("openpyxl")
    name, content, _e = SCANNERS["nessus_csv"]
    wb = openpyxl.Workbook()
    for row in csv.reader(io.StringIO(content)):
        wb.active.append(row)
    buf = io.BytesIO()
    wb.save(buf)
    assert run([("nessus_export.xlsx", buf.getvalue())]) == run([(name, content.encode())])


# ── one scan, two formats ────────────────────────────────────────────────────

def test_the_same_nessus_scan_as_nessus_and_csv_is_listed_once(run):
    import xml.etree.ElementTree as ET
    root = ET.fromstring(_nessus())
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Plugin ID", "CVE", "Risk", "Host", "Protocol", "Port", "Name", "Description", "Solution", "Plugin Output"])
    for host in root.iter("ReportHost"):
        ip = next((t.text for t in host.iter("tag") if t.get("name") == "host-ip"), host.get("name"))
        for it in host.iter("ReportItem"):
            for cve in [c.text for c in it.findall("cve")] or [""]:
                w.writerow([it.get("pluginID"), cve, it.findtext("risk_factor") or "None", ip, it.get("protocol"),
                            it.get("port"), it.get("pluginName"), it.findtext("description") or "",
                            it.findtext("solution") or "", it.findtext("plugin_output") or ""])
    alone = run([("scan.nessus", _nessus())])
    both = run([("scan.nessus", _nessus()), ("scan.csv", buf.getvalue().encode())])
    assert len(both) == len(alone)


# ── several tools in one file ────────────────────────────────────────────────

PASTED = {k: SCANNERS[k][1] for k in ("dirb", "sslscan", "medusa", "enum4linux", "nuclei_console")}


def _found(name, text):
    a, i = parse_tool_file(name, text, framework="vapt")
    return sorted((f.source_tool, f.title, f.target) for f in list(a) + list(i if isinstance(i, list) else []))


@pytest.mark.parametrize("combo", [("dirb", "sslscan"), ("medusa", "enum4linux", "nuclei_console"),
                                   ("sslscan", "dirb", "medusa")])
def test_tools_pasted_into_one_file_each_give_their_own_findings(combo):
    want = sorted(x for k in combo for x in _found(k + ".txt", PASTED[k]))
    assert _found("evidence.txt", "\n\n".join(PASTED[k] for k in combo)) == want


# ── nothing invented from a file with no vulnerability ───────────────────────

@pytest.mark.parametrize("text", [
    "WAF monthly summary\nThe WAF blocked 1,204 SQL injection attempts and 311 cross-site scripting (XSS) payloads.\n",
    "Re: Closure of findings\nThe SQL injection in the search page and the stored XSS were fixed in release 4.2.\n",
    "Secure Coding Policy\nDevelopers must use parameterised queries to prevent SQL injection.\n"
    "All output must be encoded to prevent Cross-Site Scripting.\n",
    "Change CR-2231: Upgrade OpenSSL on web01.\nRisk: Low. Risk Factor: None. Plugin output reviewed.\n",
])
def test_a_document_that_only_mentions_vulnerabilities_gives_no_findings(run, text):
    assert run([("document.txt", text.encode())]) == []


def test_a_captured_exchange_is_still_read_as_a_proof_of_concept():
    text = ("Burp Repeater\nPOST /login HTTP/1.1\nHost: portal.test\n\nusername=admin'--&password=x\n\n"
            "HTTP/1.1 500 Internal Server Error\nYou have an error in your SQL syntax\nSQL Injection confirmed\n")
    a, _i = parse_tool_file("repeater.txt", text, framework="vapt")
    assert a and all(f.confidence == "Tentative" and f.severity_score is None for f in a)


def test_a_findings_list_reads_each_findings_own_fields():
    text = ("# Vulnerability Assessment Finding Excerpt\n"
            "1. Vulnerability: Remote Code Execution via vsftpd 2.3.4 Backdoor\n   - Host: 192.168.1.105:21\n"
            "   - Severity: CRITICAL (CVSS 9.8)\n   - CVE: CVE-2011-2523\n   - POC: Sent payload triggering shell on port 6200.\n\n"
            "2. Vulnerability: Apache 2.4.49 Path Traversal & Remote Code Execution\n   - Host: 192.168.1.105:80\n"
            "   - Severity: CRITICAL (CVSS 9.8)\n   - CVE: CVE-2021-41773\n   - POC: GET /cgi-bin/.%2e/.%2e/bin/sh returned /etc/passwd.\n")
    a, _i = parse_tool_file("poc_findings.txt", text, framework="vapt")
    by = {f.title: f for f in a}
    vsftpd = by["Remote Code Execution via vsftpd 2.3.4 Backdoor"]
    apache = by["Apache 2.4.49 Path Traversal & Remote Code Execution"]
    assert (vsftpd.target, vsftpd.cve_list, vsftpd.severity_score) == ("192.168.1.105:21", ["CVE-2011-2523"], 9.8)
    assert (apache.target, apache.cve_list) == ("192.168.1.105:80", ["CVE-2021-41773"])
    assert {f.source_tool for f in a} == {"Pentest Report"}          # not Burp: nothing says Burp


# ── screenshots ──────────────────────────────────────────────────────────────

def test_an_unrecognised_screenshot_is_a_review_item_not_a_vulnerability(run, monkeypatch):
    monkeypatch.setattr(worker, "extract_text", lambda f: "Nightly database backup completed successfully\nStatus: OK")
    import src.core.parsers.doc_parsers as dp
    monkeypatch.setattr(dp, "ocr_image_row_text", lambda b: "")
    got = run([("backup_ok.png", b"\x89PNG\r\n\x1a\nfake")])
    assert len(got) == 1 and got[0][1] == "INFO" and got[0][0].startswith("Screenshot for auditor review")


def test_a_terminal_screenshot_is_read_again_row_by_row(run, monkeypatch):
    scrambled = "Starting Nmap 7.94 Nmap scan report for 10.0.0.5 PORT STATE\n21/tcp open 23/tcp open ftp telnet"
    rows = ("Starting Nmap 7.94 ( https://nmap.org )\nNmap scan report for 10.0.0.5\nPORT STATE SERVICE VERSION\n"
            "21/tcp open ftp vsftpd 2.3.4\n23/tcp open telnet Linux telnetd\n")
    monkeypatch.setattr(worker, "extract_text", lambda f: scrambled)
    import src.core.parsers.doc_parsers as dp
    monkeypatch.setattr(dp, "ocr_image_row_text", lambda b: rows)
    got = run([("nmap_console.png", b"\x89PNG\r\n\x1a\nfake")])
    assert [(t, s) for t, s, _ in got] == [("Nmap: Cleartext Remote Login Service (Telnet) (23/tcp)", "HIGH")]


# ── code and dependency scanners ─────────────────────────────────────────────

@pytest.mark.parametrize("key", sorted(CODE))
def test_code_and_dependency_scanner_exports_are_read(key):
    name, content, exp = CODE[key]
    a, i = parse_tool_file(name, content, framework="vapt")
    found = list(a) + list(i if isinstance(i, list) else [])
    assert len(found) >= exp.get("min", 0) and len(found) <= exp.get("max", 10 ** 6), [f.title for f in found]
    blob = lambda f: f"{f.title} {f.description} {f.evidence} {f.target} {' '.join(f.cve_list)}".lower()
    for m in exp.get("mention", []):
        assert any(m.lower() in blob(f) for f in found), m
    for sub, sev in exp.get("sev", {}).items():
        hits = [f for f in found if sub.lower() in (f.title + " " + " ".join(f.cve_list)).lower()]
        assert hits and all(f.severity == sev for f in hits), (sub, [f.severity for f in hits])
    for n in exp.get("none", []):
        assert not any(n in f"{f.title} {f.description} {f.evidence}" for f in found), "secret leaked"


def test_a_findings_csv_is_read_column_by_column():
    text = ("Vulnerability,Severity,Host,Description,Recommendation,Status,CVE\n"
            "SQL Injection in login form,Critical,https://portal.test/login,\"Injectable, confirmed.\",Use parameterised queries.,Open,\n"
            "Missing HSTS header,Low,https://portal.test/,HSTS not set.,Add the HSTS header.,Closed,\n")
    a, i = parse_tool_file("tracker.csv", text, framework="vapt")
    sqli = a[0]
    assert (sqli.title, sqli.severity, sqli.target, sqli.remediation) == (
        "SQL Injection in login form", "CRITICAL", "https://portal.test/login", "Use parameterised queries.")
    assert [f.title for f in i] == ["Missing HSTS header"]                  # closed: informational


# ── the model runs only when the auditor ticks AI recommendations ───────────

@pytest.fixture
def model_calls(monkeypatch):
    from src.core import llm_client
    from src.core.parsers import remediation_llm, report_narrative_llm
    calls = []
    monkeypatch.setattr(llm_client, "query_llm", lambda *a, **k: calls.append("query_llm") or "")
    monkeypatch.setattr(report_narrative_llm, "generate_report_narrative",
                        lambda *a, **k: calls.append("summary") or None)
    monkeypatch.setattr(remediation_llm, "enrich_remediations",
                        lambda *a, **k: calls.append("remediation"))
    # Even with a model up and answering, which is what the parser-only path
    # briefly checked for before asking it for the summary.
    monkeypatch.setattr(worker, "_llm_answering", lambda *a, **k: True, raising=False)
    return calls


def test_a_parser_only_scan_never_calls_the_model(run, model_calls):
    assert run([("scan.nessus", _nessus())])
    assert model_calls == []


def test_ticking_ai_recommendations_brings_the_model_in(run, model_calls):
    assert run([("scan.nessus", _nessus())], ai_recommendations=True)
    assert "remediation" in model_calls and "summary" in model_calls, model_calls


# ── a PDF's tables are read only when the report-table parser needs them ─────
# Reading them parses the whole PDF a second time: on PortSwigger's one-page
# Burp PDF that was 30 s of a 50 s scan, for rows only PentestReportParser uses.

_METHOD = ("The assessment followed the OWASP Testing Guide. Each finding below was "
           "confirmed manually and rated with CVSS 3.1. The scope covered the customer "
           "portal and its API. Testing was carried out from the internet without "
           "credentials, then with a standard user account supplied by the customer. ")

_NMAP = """Starting Nmap 7.94 ( https://nmap.org ) at 2025-06-24 10:00 IST
Nmap scan report for 10.0.0.5
Host is up (0.0010s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.3.4
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
23/tcp   open  telnet  Linux telnetd
80/tcp   open  http    Apache httpd 2.4.49 ((Unix))
3306/tcp open  mysql   MySQL 5.5.62
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"""


def _pdf(text, with_table=False):
    pytest.importorskip("reportlab")
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Preformatted, SimpleDocTemplate, Table, TableStyle
    story = [Preformatted(text, getSampleStyleSheet()["Code"])]
    if with_table:
        t = Table([["S. No", "Observation", "Severity", "Affected\nIP/URL", "CVE/CWE", "Final\nStatus"],
                   ["1.", "Cleartext\nTransmission of\nPhone Numbers", "Low (CVSS\nScore: 2.0)",
                    "https://172.21.13\n1.47:9007", "CWE-319", "Open"]])
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.black)]))
        story.append(t)
    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4).build(story)
    return buf.getvalue()


@pytest.fixture
def table_reads(monkeypatch):
    from src.core.parsers import doc_parsers
    real, calls = doc_parsers.extract_pdf_table_rows, []
    monkeypatch.setattr(doc_parsers, "extract_pdf_table_rows",
                        lambda b: calls.append(1) or real(b))
    return calls


def test_a_scanner_pdf_is_not_parsed_again_for_tables(run, table_reads):
    found = run([("nmap_scan.pdf", _pdf(_NMAP))])
    assert any(t == "10.0.0.5:23/tcp" or "telnet" in n.lower() for n, _s, t in found), found
    assert table_reads == []


def test_a_report_pdf_still_has_its_findings_table_read(run, table_reads):
    found = run([("report.pdf", _pdf("Penetration Testing Report\n\n" + _METHOD, with_table=True))])
    assert ("Cleartext Transmission of Phone Numbers", "LOW", "https://172.21.131.47:9007") in found, found
    assert table_reads == [1]


def _everything(res):
    a, i = res
    return [sorted(vars(f).items()) for f in list(a) + list(i if isinstance(i, list) else [])]


@pytest.mark.parametrize("body", [
    "Penetration Testing Report\n\n" + _METHOD,
    _NMAP,
    PASTED["dirb"] + "\n\n" + PASTED["sslscan"],      # split by tool only when there are no tables
], ids=["report", "nmap", "two-tools"])
@pytest.mark.parametrize("rows", [["1. | Cleartext Transmission of Phone Numbers | Low (CVSS Score: 2.0) | "
                                   "https://172.21.131.47:9007 | CWE-319 | Open"], []],
                         ids=["with-tables", "no-tables"])
def test_tables_read_on_demand_give_what_appended_tables_gave(body, rows):
    from src.core.parsers.pentest_report_parser import PDF_TABLES_MARKER
    appended = body + (PDF_TABLES_MARKER + "\n".join(rows) if rows else "")
    assert (_everything(parse_tool_file("x.pdf", body, framework="vapt", table_rows=lambda: list(rows)))
            == _everything(parse_tool_file("x.pdf", appended, framework="vapt")))


def test_a_compliance_export_is_not_read_as_vulnerabilities():
    text = ("UC,Scenario,Severity,Control,Finding,Recommendation,Status\n"
            "UC0,Audit,P3 Medium,Logging (8.15),Logging requirements missing from policy.,Define logging.,Non-Compliant\n"
            "UC0,Audit,P3 Medium,Clock Synchronization (8.17),NTP not documented.,Document NTP.,Non-Compliant\n")
    a, i = parse_tool_file("export.csv", text, framework="vapt")
    assert not a and not (i or [])
