# -*- coding: utf-8 -*-
"""After a retest, 2.3.1 calls closed findings closed -- not "recorded as
closed in the report", which is what a single scan's closed rows are. Most of a
retest's closed findings were closed by the retest itself."""
from src.core.report_exporter import _vapt_overview_sentence


def test_a_retest_says_closed():
    s = _vapt_overview_sentence(9, 17, 13, retest=True)
    assert s.endswith("with 17 further informational observation(s) and 13 closed finding(s):")
    assert "records as closed" not in s


def test_a_single_scan_keeps_its_wording():
    assert _vapt_overview_sentence(9, 17, 13).endswith(
        "and 13 finding(s) the report records as closed:")
