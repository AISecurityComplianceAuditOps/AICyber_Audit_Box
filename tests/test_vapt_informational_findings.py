# -*- coding: utf-8 -*-
"""A VAPT session lists its scanner's informational findings, as its report does.

The VAPT report keeps Burp's 18 informational findings (prototype pollution,
request URL override, DNS interactions...). The Audit Records page did not:
/audit/findings dropped them unless asked, the page never asked, and it
filtered them out again. An auditor could not see or review what the report
printed. Nothing in a VAPT scan is ever "Compliant", so that filter and counter
could never match; on a VAPT session Informational takes their place. ISO and
PQC sessions are unchanged.

The page's own functions are run under Node where it is available.
"""
import io
import json
import os
import re
import shutil
import subprocess

import pytest

APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "src", "api", "static", "app.js")


def _src():
    return io.open(APP_JS, encoding="utf-8").read()


def _function(src, name):
    start = src.index(f"function {name}(")
    depth, i = 0, src.index("{", start)
    while True:
        ch = src[i]
        depth += ch == "{"
        depth -= ch == "}"
        i += 1
        if depth == 0:
            return src[start:i]


def _run(payload):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    src = _src()
    parts = [_function(src, n) for n in ("isFindingInformational", "isVaptOnlySession",
                                         "syncStatusFilterForSession", "findingsForSession")]
    script = (
        "const document = { getElementById: () => null, querySelector: () => null };\n"
        "let findingsSessionFramework = '';\n"
        + "\n".join(parts)
        + f"\nconsole.log(JSON.stringify(findingsForSession({json.dumps(payload)}).map(f => f.id)));"
    )
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip())


ROWS = [{"id": 1, "severity": "HIGH", "status": "Non-Compliant"},
        {"id": 2, "severity": "INFO", "status": "Informational"}]


def test_a_vapt_session_lists_its_informational_findings():
    assert _run({"framework": "VAPT", "findings": ROWS}) == [1, 2]


@pytest.mark.parametrize("framework", ["ISO 27001", "PQC", "VAPT/PQC", ""])
def test_other_sessions_still_hide_informational_rows(framework):
    assert _run({"framework": framework, "findings": ROWS}) == [1]


def test_every_findings_loader_asks_for_informational_rows():
    """The page loads findings in three places; each must ask, or the VAPT
    list depends on how the session was opened."""
    src = _src()
    urls = re.findall(r"/audit/findings\?session_id=\$\{[a-zA-Z]+\}([^`]*)`", src)
    assert len(urls) >= 3
    loaders = [u for u in urls if "saved_only" not in u]
    assert loaders and all("include_info=true" in u for u in loaders), urls
    assert src.count("findingsForSession(") >= 4          # definition + 3 loaders


def test_the_status_filter_has_an_informational_branch():
    src = _src()
    chain = src[src.index('if (valLower !== "all") {'):][:1500]
    assert 'valLower === "informational"' in chain
    gaps = re.search(r'\} else if \(valLower\.includes\("non"\) \|\| valLower\.includes\("gap"\)\) \{\n(.*?)\n',
                     chain, re.S).group(1)
    assert "isFindingInformational" in gaps, "an informational result is not a gap"


def test_informational_results_are_not_counted_as_gaps():
    stats = _function(_src(), "calculateSeverityStats")
    assert stats.count("isFindingInformational(f)") == 2     # both counting paths
    assert "isVaptOnlySession() ? infoCount : compCount" in stats


def test_the_kpi_helper_the_loaders_call_exists():
    """updateKPICounters() was called and never defined: the ReferenceError made
    "Recent" report "Failed to load recent session" after loading it."""
    assert re.search(r"function updateKPICounters\s*\(", _src())


def test_the_severity_badge_invents_no_cvss():
    src = _src()
    block = src[src.index("const _cvss ="):][:2500]
    assert "7.5" not in block and "9.8" not in block and "2.5" not in block
    assert '"no CVSS"' in block
