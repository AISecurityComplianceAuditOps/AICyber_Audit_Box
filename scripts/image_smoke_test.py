# -*- coding: utf-8 -*-
"""Check a freshly built app image before it is packaged for a customer.

Runs INSIDE the image, with no network, the way an air-gapped site runs it:

    docker run --rm --network none --entrypoint python -e POSTGRES_PASSWORD= \
        -v "<repo>/scripts/image_smoke_test.py:/tmp/image_smoke_test.py:ro" \
        -w /app aicyberauditbox-app:<version> /tmp/image_smoke_test.py

make_update.bat runs it after the build and packages nothing if it fails.

Why: the build proves the listed libraries install, not that the application
works. A library the code imports but requirements.txt does not name builds
cleanly and fails at the customer with ImportError; the tests run on the
workstation (Windows, a newer Python), not on the image's Linux / Python 3.11.
This checks, in the image itself:

  1. every third-party module the code imports is installed
  2. the application imports
  3. the knowledge files load (CISA KEV, MITRE CWE, the PQC tables)
  4. a sample scan goes through the real worker with the right result
  5. the VAPT PDF / DOCX and the ISO PDF (LibreOffice) export

Exit code 0 when all pass, 1 otherwise. Output is plain ASCII.
"""
import ast
import importlib.util
import io
import os
import sys
import tempfile
import traceback

APP = "/app"
sys.path.insert(0, APP)
os.chdir(APP)
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

RESULTS = []


def check(name):
    def wrap(fn):
        try:
            detail = fn()
            RESULTS.append((True, name, detail or ""))
        except Exception as e:                      # noqa: BLE001 -- report every failure
            tb = traceback.format_exc().strip().splitlines()[-1]
            RESULTS.append((False, name, "%s: %s | %s" % (type(e).__name__, e, tb)))
        return fn
    return wrap


def _guarded(node, parents):
    """True when an import sits inside a try that handles its failure."""
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.Try):
            for h in node.handlers:
                names = []
                if h.type is None:
                    return True
                for t in (h.type.elts if isinstance(h.type, ast.Tuple) else [h.type]):
                    names.append(getattr(t, "id", getattr(t, "attr", "")))
                if {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"} & set(names):
                    return True
    return False


@check("every library the code imports is installed")
def _libraries():
    stdlib = set(getattr(sys, "stdlib_module_names", ())) | set(sys.builtin_module_names)
    missing = {}
    for dirpath, dirs, files in os.walk(os.path.join(APP, "src")):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                tree = ast.parse(io.open(path, encoding="utf-8").read())
            except SyntaxError as e:
                raise AssertionError("%s does not parse on this Python: %s" % (path, e))
            parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                    names = [node.module]
                else:
                    continue
                for name in names:
                    top = name.split(".")[0]
                    if top in stdlib or top == "src" or top in missing:
                        continue
                    if importlib.util.find_spec(top) is None and not _guarded(node, parents):
                        missing[top] = os.path.relpath(path, APP)
    assert not missing, "not installed: " + ", ".join("%s (imported in %s)" % kv for kv in sorted(missing.items()))
    return "all installed"


@check("the application imports")
def _app():
    import src.api.main as m
    return "%d routes" % len(m.app.routes)


@check("the knowledge files load")
def _knowledge():
    from src.core.parsers import control_mapper as cm
    from src.core.parsers import pqc_crypto_db as pq
    kev, cwe = cm._kev(), cm._cwe_kb()
    assert len(kev) > 1000, "CISA KEV has %d entries" % len(kev)
    assert len(cwe) > 500, "MITRE CWE has %d entries" % len(cwe)
    for name in ("X509_OID_DB", "IANA_CIPHER_DB", "LIBOQS_ALGO_DB", "CWE_NIST_DB"):
        assert getattr(pq, name), "%s is empty" % name
    return "KEV %d CVEs, CWE %d weaknesses, PQC tables loaded" % (len(kev), len(cwe))


NESSUS = ("<?xml version=\"1.0\" ?><NessusClientData_v2><Report name=\"smoke\"><ReportHost name=\"10.0.0.5\">"
          "<HostProperties><tag name=\"host-ip\">10.0.0.5</tag></HostProperties>"
          "<ReportItem port=\"443\" svc_name=\"www\" protocol=\"tcp\" severity=\"3\" pluginID=\"42873\" "
          "pluginName=\"SSL Medium Strength Cipher Suites Supported (SWEET32)\" pluginFamily=\"General\">"
          "<cve>CVE-2016-2183</cve><cvss3_base_score>7.5</cvss3_base_score><risk_factor>High</risk_factor>"
          "<description>Medium strength ciphers are supported.</description>"
          "<solution>Disable 3DES.</solution><plugin_output>DES-CBC3-SHA</plugin_output>"
          "</ReportItem></ReportHost></Report></NessusClientData_v2>")
TRACKER = ("Vulnerability,Severity,Host,Description,Recommendation,Status,CVE\n"
           "SQL Injection in login form,Critical,https://portal.test/login,Injectable.,Use parameterised queries.,Open,\n"
           "Missing HSTS header,Low,https://portal.test/,HSTS not set.,Add the HSTS header.,Closed,\n")
SAVED = []


@check("a sample scan goes through the worker")
def _scan():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import src.core.bg_worker as worker
    from src.db.database import AuditReport, Base, Finding
    eng = create_engine("sqlite:///" + os.path.join(tempfile.mkdtemp(), "smoke.db"))
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    worker.SessionLocal = S
    s = S()
    s.add(AuditReport(session_id="smoke", session_title="smoke", framework="VAPT"))
    s.commit()
    s.close()
    worker._run_fast_technical_vapt_bg(
        "smoke", [{"name": "scan.nessus", "bytes": NESSUS.encode(), "text": None},
                  {"name": "tracker.csv", "bytes": TRACKER.encode(), "text": None}],
        selected_sls=[], framework="VAPT", ai_recommendations=False)
    s = S()
    rows = {r.control_name: r for r in s.query(Finding).all()}
    s.close()
    got = {k: (r.severity, r.status) for k, r in rows.items()}
    want = {"SSL Medium Strength Cipher Suites Supported (SWEET32)": ("HIGH", "Non-Compliant"),
            "SQL Injection in login form": ("CRITICAL", "Non-Compliant"),
            "Missing HSTS header": ("LOW", "Closed")}
    assert got == want, "saved %r" % got
    sweet = rows["SSL Medium Strength Cipher Suites Supported (SWEET32)"]
    assert sweet.severity_score == 7.5 and "CVE-2016-2183" in (sweet.cve_refs or ""), \
        "SWEET32 saved with score %r, refs %r" % (sweet.severity_score, sweet.cve_refs)
    SAVED.extend(rows.values())
    return "3 findings saved as the sources state them"


@check("the VAPT PDF and DOCX export")
def _vapt_reports():
    from src.core.report_exporter import export_docx_report, export_pdf_report
    assert SAVED, "no findings to export (the scan check failed)"
    fs = [{"control_id": r.control_id, "title": r.control_name, "severity": r.severity, "status": r.status,
           "final_result": r.final_result, "target": r.target, "description": r.description,
           "recommendation": r.recommendation, "evidence_snippet": r.evidence_snippet,
           "remediation_actionable": r.remediation_actionable} for r in SAVED]
    pdf = export_pdf_report("smoke", fs, [], "FINAL", audit_type="vapt")
    docx = export_docx_report("smoke", fs, [], "FINAL", audit_type="vapt")
    pdf = pdf.getvalue() if hasattr(pdf, "getvalue") else pdf
    docx = docx.getvalue() if hasattr(docx, "getvalue") else docx
    assert pdf[:4] == b"%PDF" and len(pdf) > 10000, "VAPT PDF is %d bytes" % len(pdf)
    assert docx[:2] == b"PK" and len(docx) > 10000, "VAPT DOCX is %d bytes" % len(docx)
    return "PDF %d KB, DOCX %d KB" % (len(pdf) // 1024, len(docx) // 1024)


@check("the ISO PDF exports (LibreOffice)")
def _iso_report():
    from pypdf import PdfReader
    from src.core.report_exporter import export_pdf_report
    f = {"control_id": "8.17", "control_name": "8.17 Clock Synchronization", "control": "8.17 Clock Synchronization",
         "description": "NTP is enabled and the clock is synchronised.", "recommendation": "No action required.",
         "evidence_snippet": "System clock synchronized: yes", "source_files": "ntp.jpg", "severity": "N/A",
         "status": "Compliant", "final_result": "COMPLIANT"}
    pdf = export_pdf_report("smoke", [f], ["8.17"], "COMPLETED", metadata={"framework": "ISO 27001"})
    pdf = pdf.getvalue() if hasattr(pdf, "getvalue") else pdf
    text = " ".join(" ".join((p.extract_text() or "") for p in PdfReader(io.BytesIO(pdf)).pages).split())
    assert "8.17 Clock Synchronization" in text, "the ISO PDF does not show the control"
    return "%d pages" % len(PdfReader(io.BytesIO(pdf)).pages)


@check("the model server's startup script is carried for apply_update")
def _llm_config():
    # apply_update reads these two out of the app image and builds the script
    # onto the site's LLM image; without them an app update leaves the model
    # server on whatever slot sizing it shipped with.
    base = os.path.join(APP, "llm-config")
    recipe = open(os.path.join(base, "Dockerfile.llm.rebase"), "rb").read()
    script = open(os.path.join(base, "docker", "llm-entrypoint.sh"), "rb").read()
    assert b"COPY docker/llm-entrypoint.sh /llm-entrypoint.sh" in recipe, "the recipe does not copy the script"
    assert script.startswith(b"#!/bin/sh") or script.startswith(b"#!/bin/bash"), "the script has no shebang"
    assert b"\r" not in script, "the script has Windows line endings and would not run"
    assert b"STACK_RESERVE_GB" in script, "the script keeps no memory back for the app"
    return "%d KB" % (len(script) // 1024)


print("")
print("  Image check  (Python %s)" % sys.version.split()[0])
for ok, name, detail in RESULTS:
    print("    [%s] %s%s" % ("ok" if ok else "X ", name, (" -- " + detail) if detail else ""))
failed = [r for r in RESULTS if not r[0]]
print("")
print("  %s" % ("ALL CHECKS PASSED" if not failed else "%d CHECK(S) FAILED" % len(failed)))
sys.exit(1 if failed else 0)
