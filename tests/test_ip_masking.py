# -*- coding: utf-8 -*-
"""An ISO report names the host, but masked. A VAPT report never masks it.

    pytest tests/test_ip_masking.py -v

WHY THIS EXISTS

An ISO finding is worth more when it says which machine it is about --
"NTP is enabled and synchronized on host 172.16.32.xxx, per
121_NTP_Server_Clock_Sync_AUA_DB.jpg" is traceable, "on the host" is not. But
the exact address is incidental PII in a compliance report that leaves the
building, so exports mask the last octet and say so.

Exports previously replaced the whole address with "[IP REDACTED]", which took
the traceability away with the PII: two findings about two different servers
read identically.

VAPT and PQC are the opposite case and must not be touched. A vulnerable host's
address IS the report's content -- masking it would make the remediation
instruction useless. Those export paths pass redact_ip=False, and the test at
the bottom pins every one of them.
"""
import re

import pytest

from src.core.pii_redactor import redact_pii, mask_ip_last_octet


SENTENCE = ("NTP is enabled and synchronized on the host at 172.16.32.18. "
            "The same host 172.16.32.18 reports synchronized: yes.")


# ── ISO exports: masked, and said to be masked ───────────────────────────────

def test_last_octet_is_masked_and_the_subnet_survives():
    out = redact_pii(SENTENCE)
    assert "172.16.32.xxx" in out
    assert "172.16.32.18" not in out


def test_the_masking_is_declared_not_silent():
    """A reader must be able to tell the address was hidden, not mistyped."""
    assert "(IP masked)" in redact_pii(SENTENCE)


def test_the_marker_appears_once_however_often_the_host_is_named():
    """One host mentioned three times is one hidden thing, not three."""
    out = redact_pii(SENTENCE)
    assert out.count("(IP masked)") == 1
    assert out.count("172.16.32.xxx") == 2


def test_two_different_hosts_stay_distinguishable():
    """The whole point of masking rather than redacting."""
    out = redact_pii("Host 10.0.4.7 passed; host 10.0.9.31 failed.")
    assert "10.0.4.xxx" in out
    assert "10.0.9.xxx" in out


def test_email_and_phone_are_still_removed_outright():
    out = redact_pii("Contact ops@dhiware.com or +91-9876543210 about 10.1.2.3.")
    assert "[EMAIL REDACTED]" in out
    assert "[PHONE REDACTED]" in out
    assert "10.1.2.xxx" in out


# ── the feedback / knowledge-loop path: removed entirely ─────────────────────

def test_feedback_path_removes_the_address_completely():
    """This text is replayed verbatim into a later audit's prompt, where an
    address is of no use to anyone."""
    out = redact_pii(SENTENCE, ip_style="redact")
    assert "[IP REDACTED]" in out
    assert "172.16.32" not in out
    assert "xxx" not in out


# ── VAPT / PQC: never touched ────────────────────────────────────────────────

def test_vapt_keeps_the_full_address():
    out = redact_pii("Redis on 172.16.32.18:6379 is unauthenticated.", redact_ip=False)
    assert "172.16.32.18" in out
    assert "xxx" not in out
    assert "REDACTED" not in out


def test_vapt_still_strips_email_and_phone():
    out = redact_pii("Owner ops@dhiware.com, host 10.0.0.5", redact_ip=False)
    assert "[EMAIL REDACTED]" in out
    assert "10.0.0.5" in out


def test_every_vapt_export_call_site_still_passes_redact_ip_false():
    """The VAPT/PQC report layouts must never acquire a masked address.

    Read off the source: these call sites are what keeps a pentest report
    actionable, and a well-meaning "mask IPs everywhere" change would break
    them silently -- the report would still render, just uselessly.
    """
    import io
    import os
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "src", "core", "report_exporter.py")
    with io.open(path, encoding="utf-8") as fh:
        src = fh.read()
    assert src.count("redact_ip=False") >= 6, (
        "a VAPT/PQC export call site lost its redact_ip=False -- that report's "
        "host addresses would be masked, making remediation unactionable"
    )


# ── the helper on its own ────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("172.16.32.18", "172.16.32.xxx"),
    ("10.0.0.1", "10.0.0.xxx"),
    ("192.168.1.254", "192.168.1.xxx"),
])
def test_mask_helper_keeps_three_octets(raw, expected):
    assert mask_ip_last_octet(raw, marker="") == expected


@pytest.mark.parametrize("passthrough", ["", None, 12345, "no address here"])
def test_mask_helper_leaves_everything_else_alone(passthrough):
    assert mask_ip_last_octet(passthrough) == passthrough


def test_masked_output_is_not_a_valid_address():
    """So nothing downstream can mistake it for a real host and try to reach it."""
    out = mask_ip_last_octet("172.16.32.18", marker="")
    assert not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", out)
