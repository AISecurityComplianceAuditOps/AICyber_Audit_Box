# -*- coding: utf-8 -*-
"""A retested VAPT session shows the outcome -- Open or Closed -- not a comparison.

    pytest tests/test_vapt_retest_open_closed_ui.py -v

Asked for by the reviewers of the retest feature:

  * the scan versions were a row of buttons that ran off the panel after a few
    retests; they are now one dropdown, latest first;
  * five categories (still open, fixed, new, not retested, reopened) read as a
    comparison; the bar now counts Open and Closed, as the report does, and
    filters on them. Closed is isFindingClosed(), the same rule the card's own
    badge and the report use, so the card carries no second status badge;
  * the Report Exporter offers which version to download (latest by default),
    and no comparison summary: every version's report gives Open or Closed.

Verified in the real UI (Playwright, Edge) with the retest demo files: v1 37
found, v2 retest 24 found -> 26 Open, 13 Closed on screen and in the report.
"""
import io
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, "src", "api", "static", "app.js")
INDEX = os.path.join(ROOT, "src", "api", "static", "index.html")


def _src(path):
    return io.open(path, encoding="utf-8").read()


def _fn(src, name):
    m = re.search(r"\n(?:async )?function " + re.escape(name) + r"\(.*?\n\}", src, re.S)
    assert m, "%s not found in app.js" % name
    return m.group(0)


def test_the_versions_are_one_dropdown():
    bar = _fn(_src(APP_JS), "renderVaptRetestBar")
    assert '<select id="vapt-version-select"' in bar
    assert 'onchange="setVaptViewRound(this.value)"' in bar
    assert "vapt-version-btn" not in _src(APP_JS)


def test_the_bar_counts_open_and_closed_only():
    src = _src(APP_JS)
    bar = _fn(src, "renderVaptRetestBar")
    assert '["open", "closed"]' in bar
    for word in ("still_open", "not_retested", "compared with"):
        assert word not in bar, word
    assert "isFindingClosed(f)" in _fn(src, "vaptFinalStatusKey")
    # Counted over what the report lists, so the two numbers match it.
    assert "vaptInReport" in _fn(src, "vaptRetestCounts")


def test_the_filter_uses_the_same_open_or_closed():
    assert "vaptFinalStatusKey(f) === vaptRetestFilter" in _src(APP_JS)


def test_a_card_has_one_status_badge():
    assert "vaptRetestBadgeHtml" not in _src(APP_JS)


def test_the_exporter_offers_the_version_and_no_comparison():
    src, index = _src(APP_JS), _src(INDEX)
    assert '<select id="vapt-export-round"' in index
    for text in (index, src):
        assert "vapt-export-summary" not in text and "retest_summary" not in text
    params = _fn(src, "vaptExportParams")
    # The latest is the default and sends nothing; an older one sends version=n.
    assert "n < vaptLatestRound()" in params and "&version=" in params
    for name in ("exportFindingsPDF", "exportFindingsDOCX"):
        assert "vaptExportParams()" in _fn(src, name), name
