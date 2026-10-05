# -*- coding: utf-8 -*-
"""A VAPT retest compared with the scan before it -- the rules.

    pytest tests/test_vapt_retest.py -v

See src/core/vapt_retest.py. The worker, API and page tests are in
test_vapt_retest_flow.py.
"""
import pytest

from src.core import vapt_retest as rt


# ── which hosts a target names ───────────────────────────────────────────────

@pytest.mark.parametrize("target, hosts", [
    ("https://ginandjuice.shop/catalog/product/stock [request body]", {"ginandjuice.shop"}),
    ("10.20.30.40:443/tcp (www)", {"10.20.30.40"}),
    ("10.0.0.5 / web01:443", {"10.0.0.5", "web01"}),
    ("198.51.100.93, 203.0.113.52", {"198.51.100.93", "203.0.113.52"}),
    ("Scoped Host Targets, 198.51.100.93", {"198.51.100.93"}),
    ("portal.bank.test", {"portal.bank.test"}),
    ("Not recorded", set()),
    ("Web Application Endpoint", set()),
    ("", set()),
    ("web01", set()),          # a bare word is not taken for a host
])
def test_hosts_of(target, hosts):
    assert rt.hosts_of(target) == hosts


def test_two_export_formats_of_one_location_agree():
    assert rt.location_key("https://ginandjuice.shop:443/catalog/filter [category parameter]") == \
        rt.location_key("ginandjuice.shop/catalog/filter [Category parameter]")
    assert rt.location_key("10.20.30.40:443/tcp (www)") == rt.location_key("10.20.30.40:443")
    assert rt.location_key("10.20.30.40:22/tcp") != rt.location_key("10.20.30.40:443/tcp")
    assert rt.location_key("https://shop.test/search/3 [term]") != rt.location_key("https://shop.test/search/5 [term]")


# ── the comparison ───────────────────────────────────────────────────────────

def _prev(i, title, target, status="Non-Compliant", key=None, **kw):
    d = {"id": i, "title": title, "target": target, "status": status, "final_result": None,
         "severity": kw.pop("severity", "HIGH"), "dedup_key": key or f"burp:{title.lower()}|target:{target.lower()}",
         "cve_list": kw.pop("cve_list", []), "first_round": None, "retest_status": kw.pop("retest_status", None),
         "history": kw.pop("history", [])}
    d.update(kw)
    return d


def _cur(title, target, status="Non-Compliant", key=None, **kw):
    d = {"title": title, "target": target, "status": status, "severity": kw.pop("severity", "HIGH"),
         "dedup_key": key or f"burp:{title.lower()}|target:{target.lower()}", "cve_list": kw.pop("cve_list", [])}
    d.update(kw)
    return d


SHOP = "https://ginandjuice.shop"


def test_the_mentors_case_open_fixed_new_and_not_retested():
    prev = [
        _prev(1, "SQL injection", SHOP + "/catalog/filter [category]"),
        _prev(2, "SQL injection", SHOP + "/catalog/product/stock [request body]"),
        _prev(3, "XML external entity injection", SHOP + "/catalog/product/stock"),
        _prev(4, "SMB signing not required", "10.20.30.41:445/tcp (cifs)", severity="MEDIUM"),
        _prev(5, "TLS version 1.0 protocol detection", "10.20.30.40:443/tcp (www)", severity="MEDIUM"),
    ]
    cur = [
        _cur("SQL injection", SHOP + "/catalog/product/stock [request body]"),
        _cur("TLS version 1.0 protocol detection", "10.20.30.40:443/tcp (www)", severity="MEDIUM"),
        _cur("Cross-site scripting (stored)", SHOP + "/blog/comment [comment]"),
    ]
    plan = rt.compare(prev, cur, 2, date="2026-09-26")
    u = plan["updates"]
    assert u[2]["retest_status"] == rt.STILL_OPEN and u[2]["status"] is None
    assert u[5]["retest_status"] == rt.STILL_OPEN
    for fixed in (1, 3):                      # ginandjuice.shop was rescanned
        assert u[fixed]["retest_status"] == rt.FIXED
        assert (u[fixed]["status"], u[fixed]["final_result"]) == ("Closed", "CLOSED")
    # 10.20.30.41 was not in the retest: never called fixed
    assert u[4]["retest_status"] == rt.NOT_RETESTED and u[4]["status"] is None
    assert [n["title"] for n in plan["new"]] == ["Cross-site scripting (stored)"]
    assert plan["new"][0]["retest_status"] == rt.NEW and plan["new"][0]["first_round"] == 2
    assert plan["counts"] == {"still_open": 2, "fixed": 2, "new": 1, "not_retested": 1, "reopened": 0}
    assert plan["hosts"] == ["10.20.30.40", "ginandjuice.shop"]


def test_history_keeps_the_first_version_and_adds_this_one():
    plan = rt.compare([_prev(1, "SQL injection", SHOP + "/a")], [], 2, date="2026-09-26")
    h = plan["updates"][1]["history"]
    assert h[0] == {"round": 1, "state": rt.FOUND, "status": "Non-Compliant", "date": ""}
    assert h[1]["round"] == 2 and h[1]["state"] == rt.NOT_SCANNED


def test_a_placeholder_target_is_never_called_fixed():
    prev = [_prev(1, "Reflected XSS", "Web Application Endpoint")]
    plan = rt.compare(prev, [_cur("Something else", SHOP + "/x")], 2)
    assert plan["updates"][1]["retest_status"] == rt.NOT_RETESTED
    assert plan["updates"][1]["status"] is None


def test_a_finding_on_several_hosts_is_fixed_only_when_all_were_rescanned():
    prev = [_prev(1, "Weak SSH ciphers", "198.51.100.93, 203.0.113.52")]
    only_one = rt.compare(prev, [_cur("Other", "198.51.100.93:22/tcp")], 2)
    assert only_one["updates"][1]["retest_status"] == rt.NOT_RETESTED
    both = rt.compare(prev, [_cur("Other", "198.51.100.93:22/tcp"), _cur("Other 2", "203.0.113.52:80/tcp")], 2)
    assert both["updates"][1]["retest_status"] == rt.FIXED


def test_the_same_finding_from_another_export_format_still_matches():
    """Same issue, same place, different key (tool name / plugin id changed)."""
    prev = [_prev(1, "SQL injection", SHOP + "/catalog/filter [category parameter]", key="burp-pdf-key")]
    cur = [_cur("SQL Injection", "ginandjuice.shop:443/catalog/filter [Category parameter]", key="other-key")]
    plan = rt.compare(prev, cur, 2)
    assert plan["updates"][1]["retest_status"] == rt.STILL_OPEN
    assert plan["new"] == []


def test_the_portswigger_pdf_and_html_write_one_finding_two_ways():
    """Measured on the real reports: the same 35-issue scan as PDF then HTML
    gave 21 false 'fixed' + 21 'new' before the location was read from the
    title and the target together."""
    prev = [_prev(1, "SQL injection (https://ginandjuice.shop/catalog/filter [category parameter])",
                  "https://ginandjuice.shop/catalog/filter [category parameter]", key="k-pdf")]
    cur = [_cur("SQL injection (/catalog/filter [category parameter])",
                "https://ginandjuice.shop/catalog/filter", key="k-html")]
    plan = rt.compare(prev, cur, 2)
    assert plan["updates"][1]["retest_status"] == rt.STILL_OPEN and plan["new"] == []


# Burp's XML export writes the target as the host and path, then the issue's
# location in brackets. Measured: the PortSwigger PDF as v1 and the Burp XML
# of the same site as v2 gave every issue found again as Fixed and New both.
PDF_SQLI = ("SQL injection (https://ginandjuice.shop/catalog/filter [category parameter])",
            "https://ginandjuice.shop/catalog/filter [category parameter]")
XML_SQLI = ("SQL injection", "https://ginandjuice.shop/catalog/filter (/catalog/filter [category parameter])")


@pytest.mark.parametrize("title, target", [
    PDF_SQLI, XML_SQLI,
    ("SQL injection (/catalog/filter [category parameter])", "https://ginandjuice.shop/catalog/filter"),
])
def test_the_pdf_html_and_xml_forms_name_one_place(title, target):
    assert rt.issue_and_location(title, target) == (
        "sql injection", "ginandjuice.shop", "ginandjuice.shop/catalog/filter [category parameter]")


@pytest.mark.parametrize("pdf_target, xml_target", [
    ("https://ginandjuice.shop/", "https://ginandjuice.shop/ (/)"),
    ("https://ginandjuice.shop/catalog/product/stock", "https://ginandjuice.shop/catalog/product/stock (/catalog/product/stock)"),
])
def test_the_xml_form_without_a_parameter(pdf_target, xml_target):
    assert rt.issue_and_location("x", pdf_target) == rt.issue_and_location("x", xml_target)


def test_the_portswigger_pdf_then_its_burp_xml_retest():
    prev = [_prev(1, *PDF_SQLI, key="k-pdf"),
            _prev(2, "SQL injection (https://ginandjuice.shop/catalog/product/stock [request body])",
                  "https://ginandjuice.shop/catalog/product/stock [request body]", key="k-pdf-2")]
    cur = [_cur(*XML_SQLI, key="k-xml"),
           _cur("Cross-site request forgery", "https://ginandjuice.shop/my-account/change-email "
                "(/my-account/change-email)", key="k-xml-2", severity="MEDIUM")]
    plan = rt.compare(prev, cur, 2)
    assert plan["updates"][1]["retest_status"] == rt.STILL_OPEN
    assert plan["updates"][2]["retest_status"] == rt.FIXED          # the host was rescanned
    assert [n["title"] for n in plan["new"]] == ["Cross-site request forgery"]
    assert plan["counts"] == {"still_open": 1, "fixed": 1, "new": 1, "not_retested": 0, "reopened": 0}


def test_an_xml_location_at_another_url_is_still_another_finding():
    prev = [_prev(1, "Cross-site scripting (reflected) (https://ginandjuice.shop/catalog/search/3 [term parameter])",
                  "https://ginandjuice.shop/catalog/search/3 [term parameter]", key="k-pdf")]
    cur = [_cur("Cross-site scripting (reflected)",
                "https://ginandjuice.shop/catalog/search/5 (/catalog/search/5 [term parameter])", key="k-xml")]
    plan = rt.compare(prev, cur, 2)
    assert plan["updates"][1]["retest_status"] == rt.FIXED
    assert [n["target"] for n in plan["new"]] == [cur[0]["target"]]


def test_a_service_name_in_brackets_is_not_read_as_a_location():
    assert rt.issue_and_location("TLS 1.0", "10.20.30.40:443/tcp (www)")[2] == "10.20.30.40:443"


def test_a_finding_listed_with_every_host_matches_its_per_host_rows():
    """Nessus by plugin lists one finding with all its hosts; by host lists it
    once per host. Measured on a real pair of exports of one scan: 97 false
    'fixed' + 201 'new' before findings were compared host by host."""
    prev = [_prev(1, "SMB Signing not required", "13.126.199.93:445/tcp (cifs), 3.108.211.52:445/tcp (cifs)",
                  key="nessus:57608|target:13.126.199.93:445/tcp, 3.108.211.52:445/tcp")]
    cur = [_cur("SMB Signing not required", "3.108.211.52:445/tcp (cifs)", key="nessus:57608|target:3.108.211.52:445/tcp"),
           _cur("SMB Signing not required", "13.126.199.93:445/tcp (cifs)", key="nessus:57608|target:13.126.199.93:445/tcp")]
    plan = rt.compare(prev, cur, 2)
    assert plan["updates"][1]["retest_status"] == rt.STILL_OPEN and plan["new"] == []
    # And the other way round: two per-host rows, one listing.
    back = rt.compare([_prev(1, cur[0]["title"], cur[0]["target"], key=cur[0]["dedup_key"]),
                       _prev(2, cur[1]["title"], cur[1]["target"], key=cur[1]["dedup_key"])],
                      [_cur(prev[0]["title"], prev[0]["target"], key=prev[0]["dedup_key"])], 2)
    assert {u["retest_status"] for u in back["updates"].values()} == {rt.STILL_OPEN} and back["new"] == []


def test_found_on_one_of_its_hosts_is_still_open():
    prev = [_prev(1, "Weak SSH ciphers", "198.51.100.93:22/tcp, 203.0.113.52:22/tcp")]
    cur = [_cur("Weak SSH ciphers", "198.51.100.93:22/tcp", key="other"),
           _cur("Unrelated", "203.0.113.52:80/tcp")]
    assert rt.compare(prev, cur, 2)["updates"][1]["retest_status"] == rt.STILL_OPEN


def test_a_name_in_brackets_is_part_of_the_issue_not_a_location():
    assert rt.split_title("SSL Medium Strength Cipher Suites Supported (SWEET32)") == \
        ("SSL Medium Strength Cipher Suites Supported (SWEET32)", "")
    assert rt.split_title("SQL injection (/catalog/filter [category parameter])") == \
        ("SQL injection", "/catalog/filter [category parameter]")


def test_same_cves_at_the_same_place_match_across_scanners():
    prev = [_prev(1, "Apache 2.4.x < 2.4.62 Multiple Vulnerabilities", "10.20.30.40:443/tcp (www)",
                  key="nessus:201198|target:10.20.30.40:443/tcp", cve_list=["CVE-2024-38474"])]
    cur = [_cur("Apache HTTP Server Multiple Vulnerabilities", "10.20.30.40:443",
                key="qualys:38912|target:10.20.30.40:443", cve_list=["CVE-2024-38474"])]
    plan = rt.compare(prev, cur, 2)
    assert plan["updates"][1]["retest_status"] == rt.STILL_OPEN and plan["new"] == []


def test_the_same_issue_at_another_url_is_not_taken_for_the_old_one():
    """XSS fixed on /search/3, a new XSS on /search/5: fixed + new, not 'still open'."""
    prev = [_prev(1, "Cross-site scripting (reflected)", SHOP + "/catalog/search/3 [term]")]
    cur = [_cur("Cross-site scripting (reflected)", SHOP + "/catalog/search/5 [term]")]
    plan = rt.compare(prev, cur, 2)
    assert plan["updates"][1]["retest_status"] == rt.FIXED
    assert [n["target"] for n in plan["new"]] == [SHOP + "/catalog/search/5 [term]"]


def test_a_row_the_retest_report_marks_closed_is_fixed():
    prev = [_prev(1, "Missing HSTS header", SHOP + "/")]
    cur = [_cur("Missing HSTS header", SHOP + "/", status="Closed", report_status="Closed")]
    u = rt.compare(prev, cur, 2)["updates"][1]
    assert u["retest_status"] == rt.FIXED and u["status"] == "Closed"
    assert u["history"][-1]["state"] == rt.REPORTED_CLOSED


def test_a_fixed_finding_found_again_is_reopened():
    prev = [_prev(1, "SQL injection", SHOP + "/a", status="Closed", final_result="CLOSED", retest_status=rt.FIXED)]
    u = rt.compare(prev, [_cur("SQL injection", SHOP + "/a")], 3)["updates"][1]
    assert u["retest_status"] == rt.REOPENED
    assert (u["status"], u["final_result"]) == ("Non-Compliant", "")


def test_a_fixed_finding_still_absent_stays_as_it_was():
    prev = [_prev(1, "SQL injection", SHOP + "/a", status="Closed", final_result="CLOSED", retest_status=rt.FIXED)]
    u = rt.compare(prev, [_cur("Other", SHOP + "/b")], 3)["updates"][1]
    assert u["retest_status"] == rt.FIXED and u["status"] is None


def test_an_informational_finding_reopens_as_informational():
    prev = [_prev(1, "Cacheable HTTPS response", SHOP + "/", status="Closed", final_result="CLOSED", severity="INFO")]
    u = rt.compare(prev, [_cur("Cacheable HTTPS response", SHOP + "/", severity="INFO")], 2)["updates"][1]
    assert u["status"] == "Informational"


def test_a_rejected_finding_is_left_alone():
    prev = [_prev(1, "False positive XSS", SHOP + "/a", status="Rejected")]
    plan = rt.compare(prev, [_cur("Other", SHOP + "/b")], 2)
    assert plan["updates"] == {}
    assert plan["counts"]["fixed"] == 0


def test_a_new_row_reported_closed_is_not_counted_as_new():
    plan = rt.compare([], [_cur("Old issue", SHOP + "/x", status="Closed", report_status="Closed")], 2)
    assert plan["new"][0]["retest_status"] is None
    assert plan["counts"]["new"] == 0


def test_matching_is_one_to_one():
    prev = [_prev(1, "SQL injection", SHOP + "/a"), _prev(2, "SQL injection", SHOP + "/a", key="k2")]
    plan = rt.compare(prev, [_cur("SQL injection", SHOP + "/a")], 2)
    states = sorted(u["retest_status"] for u in plan["updates"].values())
    assert states == [rt.FIXED, rt.STILL_OPEN]


# ── versions and the view of an earlier one ─────────────────────────────────

def test_scanned_files_and_round_entries():
    rounds = [rt.round_entry(1, ["a.pdf"], [3], ["shop.test"], 5, date="2026-09-12"),
              rt.round_entry(2, ["a.pdf"], [7], ["shop.test"], 4, counts={"fixed": 2}, date="2026-09-26")]
    # By id: the retest file may share the first one's name.
    assert rt.scanned_files(rounds) == ({3, 7}, set())
    # A version reconstructed for an older session has names only.
    legacy = [rt.round_entry(1, ["old.pdf"], [], [], 5), rt.round_entry(2, ["new.pdf"], [9], [], 2)]
    assert rt.scanned_files(legacy) == ({9}, {"old.pdf"})
    assert rt.load_rounds(__import__("json").dumps(rounds))[1]["counts"] == {"fixed": 2}
    assert rt.load_rounds("not json") == [] and rt.load_rounds(None) == []


def test_the_view_of_an_earlier_version():
    history = '[{"round": 1, "state": "found", "status": "Non-Compliant"}, {"round": 2, "state": "not_found", "status": "Closed"}]'
    findings = [
        {"id": 1, "status": "Closed", "final_result": "CLOSED", "first_round": 1, "retest_history": history},
        {"id": 2, "status": "Non-Compliant", "final_result": None, "first_round": 2, "retest_history": None},
        {"id": 3, "status": "Non-Compliant", "final_result": None, "first_round": None, "retest_history": None},
    ]
    v1 = rt.view_as_of_round(findings, 1)
    assert [f["id"] for f in v1] == [1, 3]
    assert v1[0]["status"] == "Non-Compliant" and v1[0]["final_result"] == ""
    v2 = rt.view_as_of_round(findings, 2)
    assert [f["status"] for f in v2] == ["Closed", "Non-Compliant", "Non-Compliant"]


def test_target_of_falls_back_to_the_proof():
    assert rt.target_of("", "Target Host: 10.0.0.5:443/tcp\nScanner: Nessus") == "10.0.0.5:443/tcp"
    assert rt.target_of("shop.test", "Target Host: other") == "shop.test"
