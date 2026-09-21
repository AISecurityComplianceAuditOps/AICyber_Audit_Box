# -*- coding: utf-8 -*-
"""The VAPT PDF must export where it runs, and be readable when it does.

    pytest tests/test_vapt_pdf_export.py -v

WHY THIS EXISTS

Downloading a VAPT report answered 500 on every customer installation.

_default_auditor_logo returns None when there is no logo to be had, and the
VAPT exporter passed that straight to os.path.exists -- which raises TypeError
on None rather than returning False. It is always None on a customer machine:
the logos live in data/assets, and that directory is deliberately not in the
app image (it is a volume, because it also holds uploaded evidence), so until
somebody uploads a logo there is nothing there at all.

Seven other exporters already wrote `logo_path and os.path.exists(logo_path)`.
Only the two lines in the VAPT exporter did not, which is exactly why ISO and
PQC exports were fine and VAPT alone failed -- and why it never reproduced in
development, where data/assets exists.

The second half is the proof-of-concept block, the part of the report a reader
actually studies. It was left-stripping every line, which flattens the
indentation nmap and JSON carry their structure in; splitting on bare words
like "Date:" and "Server:" whether or not the evidence was HTTP; and leaving
long lines to the PDF, which breaks them mid-token.
"""
import io
import os
import re

import pytest

import src.core.report_exporter as rx


FINDING = {
    "control_id": "VAPT-001",
    "control_name": "Deprecated TLS versions accepted",
    "severity": "P2 High",
    "status": "Non-Compliant",
    "final_result": "NON_COMPLIANT",
    "asset_name": "web-01",
    "port": "443",
    "description": "The service negotiates TLS 1.0 and 1.1.",
    "recommendation": "Disable TLS 1.0 and 1.1; require TLS 1.2 or better.",
    "evidence_snippet": "sslscan web-01:443 | TLSv1.0  enabled",
    "source_files": "nmap_scan.xml",
}


def _export(**kw):
    args = dict(session_title="VAPT Audit Report", findings=[dict(FINDING)],
                resolved_list=[], status="Final", comments="test",
                metadata={"brand_firm": "Dhiware Technologies Pvt Ltd"})
    args.update(kw)
    out = rx._export_vapt_pdf(**args)
    return out.getvalue() if hasattr(out, "getvalue") else out


def test_it_exports_when_there_is_no_logo(monkeypatch):
    """The customer case: no logo uploaded, so no logo file anywhere.

    This is the 500. _default_auditor_logo returns None and os.path.exists(None)
    raises, so the export died before writing a page.
    """
    monkeypatch.setattr(rx, "_default_auditor_logo", lambda _dir: None)
    data = _export()
    assert data[:4] == b"%PDF", "the VAPT export did not produce a PDF without a logo"
    assert len(data) > 5000


def test_os_path_exists_still_raises_on_none():
    """The assumption the fix rests on, pinned so it cannot quietly change.

    If a future Python returns False here instead of raising, the guard is
    merely redundant rather than load-bearing -- but while it raises, every
    unguarded call is a 500 waiting for a site with no logo.
    """
    with pytest.raises(TypeError):
        os.path.exists(None)


def test_no_exporter_passes_a_possibly_none_path_unguarded():
    """Every os.path.exists on a logo path must be guarded by the path itself.

    Checked across the module rather than on the two lines that were broken:
    the same mistake is available to all nine exporters, and seven of them were
    already written correctly, which is the only reason this was one bug and
    not nine.
    """
    src = io.open(rx.__file__, encoding="utf-8").read()
    bad = re.findall(r'(?<!and )os\.path\.exists\((logo_path|effective_logo|effective_custom_logo)\)', src)
    assert not bad, (
        "unguarded os.path.exists on a path that can be None: %r -- write "
        "`x and os.path.exists(x)`" % (bad,))


# ─────────────────────────────── proof of concept ──────────────────────────

def _formatter():
    """format_http_evidence, lifted out of the exporter it is nested in."""
    src = io.open(rx.__file__, encoding="utf-8").read()
    start = src.index("        def format_http_evidence(txt):")
    end = src.index("        clean_poc = format_http_evidence", start)
    body = "\n".join(l[8:] if l.startswith("        ") else l
                     for l in src[start:end].splitlines())
    ns = {"re": re}
    exec(body, ns)
    return ns["format_http_evidence"]


def test_indentation_survives():
    """nmap and JSON carry their meaning in leading whitespace."""
    nmap = ("PORT     STATE SERVICE\n"
            "| ssl-enum-ciphers:\n"
            "|   TLSv1.0:\n"
            "|     ciphers:\n"
            "|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C")
    out = _formatter()(nmap)
    assert "|   TLSv1.0:" in out, "the nesting was flattened"
    assert "|       TLS_RSA_WITH_3DES" in out


def test_http_on_one_line_is_given_its_breaks_back():
    one_line = ('GET /admin HTTP/1.1 Host: web-01 Accept: */* '
                'HTTP/1.1 200 OK Server: nginx')
    out = _formatter()(one_line).splitlines()
    assert out[0].startswith("GET /admin")
    assert any(l.startswith("Host:") for l in out)
    assert any(l.startswith("Server:") for l in out)


def test_prose_is_not_torn_apart_at_words_that_look_like_headers():
    """The split used to run on every kind of evidence, so a sentence
    mentioning a date or a server was broken at those words."""
    prose = ("The scan was run on Date: 2026-09-21 against Server: web-01 "
             "and no HSTS header was returned.")
    out = _formatter()(prose)
    assert out.count("\n") == 0, "prose was split as though it were HTTP: %r" % out


def test_long_lines_are_wrapped_where_we_choose():
    """Left to the PDF, a hash or a URL breaks at whatever column runs out."""
    out = _formatter()("hash=" + ("a1b2c3d4" * 22)).splitlines()
    assert len(out) > 1, "a 180-character token was not wrapped"
    assert all(len(l) <= 112 for l in out), [len(l) for l in out]
    assert out[0].endswith("\\"), "a wrapped line is not marked as continuing"


def test_blank_runs_collapse_and_empty_gets_a_placeholder():
    fmt = _formatter()
    assert fmt("a\n\n\n\n\nb") == "a\n\nb"
    for empty in ("", "   ", None):
        assert fmt(empty) == "Console / Log Audit Verification"
