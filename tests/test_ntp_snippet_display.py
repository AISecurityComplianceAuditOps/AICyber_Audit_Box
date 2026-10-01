# -*- coding: utf-8 -*-
"""The finding card summarises clock-sync evidence only when the text states a
sync status.

formatEvidenceSnippet (app.js) turned any text mentioning "ntp" or "clock"
into a "TERMINAL SYSTEM EVIDENCE" summary, and with no "synchronized: yes" in
it printed "NTP Clock Synchronized: NO / Unconfirmed". An ISO 8.17 card showed
that under Documented Policy Statements for a policy that says only that
servers "shall synchronise their system clocks with an approved internal NTP
source" -- directly above evidence reading YES. Display only; the verdict was
not affected. Node is not required: the gate is mirrored here and app.js is
checked for the same rule.
"""
import os
import re

import pytest

APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "src", "api", "static", "app.js")

SYNC_STATUS = r"synchronized:\s*(yes|no)\b|ntp\s+active"
MENTIONS = r"ntp|timedatectl|clock|mobaxterm|root@|systemd-timesyncd|chronyd"

POLICY = ("DEMO LTD - INFORMATION SECURITY POLICY (extract)\nSection 8.17 Clock Synchronisation\n"
          "All production servers shall synchronise their system clocks with an approved\n"
          "internal NTP source. Synchronisation status is reviewed quarterly.")
TIMEDATECTL_YES = ("[root@demo-server ~]# timedatectl status\n    NTP enabled: yes\n"
                   "NTP synchronized: yes\n RTC in local TZ: no")
TIMEDATECTL_NO = TIMEDATECTL_YES.replace("NTP synchronized: yes", "NTP synchronized: no")


def _summarised(snip):
    """isTerminalOrNtp in formatEvidenceSnippet."""
    return bool(re.search(SYNC_STATUS, snip, re.I)) and bool(re.search(MENTIONS, snip, re.I))


def test_app_js_uses_this_rule():
    with open(APP_JS, encoding="utf-8") as fh:
        js = fh.read()
    assert "const hasSyncStatus = /synchronized:\\s*(yes|no)\\b|ntp\\s+active/i.test(snip);" in js
    assert "const isTerminalOrNtp = hasSyncStatus && /" + MENTIONS + "/i.test(snip);" in js


def test_policy_prose_about_ntp_is_quoted_not_summarised():
    assert not _summarised(POLICY)


@pytest.mark.parametrize("snip", [TIMEDATECTL_YES, TIMEDATECTL_NO])
def test_terminal_output_with_a_status_is_still_summarised(snip):
    assert _summarised(snip)
