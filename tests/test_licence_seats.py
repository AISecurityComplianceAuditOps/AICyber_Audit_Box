"""Seats had to mean something. They meant nothing.

The licence carried "seats: 16", signed and stored, and no line of the product
ever read it -- so the seventeenth simultaneous audit started exactly like the
first. Frameworks and expiry were enforced; seats were decoration.

Seats here means simultaneous audits, not accounts: creating users is unlimited
and always was.
"""
import os
import tempfile
from datetime import date, timedelta

import pytest

from src.core.licence_entitlements import Entitlements


def _ent(seats, enforcing=True):
    return Entitlements(enforcing=enforcing, frameworks={"ISO27001"},
                        customer="X", expires=date.today() + timedelta(days=365),
                        reason="test", seats=seats)


# -- the lower of the two limits wins ----------------------------------------
# Both are real and neither replaces the other: sixteen bought on a four-core
# box still cannot finish more than four, and a large box may not exceed what
# was sold.

@pytest.mark.parametrize("seats,hardware,expected", [
    (16, 16, 16),      # they match
    (16, 2, 2),        # licensed generously, four-core machine -- hardware wins
    (4, 16, 4),        # big machine, small licence -- the licence wins
    (1, 16, 1),
    (32, 16, 16),
])
def test_the_effective_limit_is_the_lower_one(seats, hardware, expected):
    assert _ent(seats).concurrent_limit(hardware) == expected


def test_a_licence_naming_no_seats_is_not_retroactively_capped():
    """Every licence issued before this existed carries no figure.

    Those installations keep running on hardware capacity, rather than being
    limited by a field nobody had ever read.
    """
    assert _ent(None).concurrent_limit(16) == 16
    assert _ent(0).concurrent_limit(16) == 16


def test_enforcement_off_ignores_seats_entirely():
    """The state every existing installation is in."""
    assert _ent(1, enforcing=False).concurrent_limit(16) == 16


# -- end to end, through a real signed licence -------------------------------

@pytest.fixture
def licensed(monkeypatch, tmp_path):
    studio = r"C:\Users\veeresh988V\Desktop\AuditBox-Release-Studio"
    if not os.path.isdir(studio):
        pytest.skip("the release studio is not on this machine")
    import sys
    sys.path.insert(0, studio)
    from studio.licensing import generate_keypair, load_private_key, issue
    priv_pem, pub_pem = generate_keypair()
    pub = tmp_path / "licence_public.pem"
    pub.write_bytes(pub_pem)

    def issue_for(seats):
        key = issue(load_private_key(priv_pem), customer="STPI",
                    expires=date.today() + timedelta(days=365),
                    frameworks=["PQC"], seats=seats)
        monkeypatch.setenv("AUDITBOX_ENFORCE_ENTITLEMENTS", "1")
        monkeypatch.setenv("AUDITBOX_LICENCE", key)
        monkeypatch.setenv("AUDITBOX_LICENCE_PUBKEY", str(pub))
        from src.core.licence_entitlements import load_entitlements
        return load_entitlements(refresh=True)
    return issue_for


def test_seats_survive_signing_and_verification(licensed):
    e = licensed(16)
    assert e.seats == 16
    assert e.concurrent_limit(32) == 16


def test_a_forged_seat_count_is_rejected_with_the_whole_licence(licensed, monkeypatch):
    """Seats are inside the signed payload, so editing them breaks the signature."""
    import base64, json
    from src.core.licence_entitlements import load_entitlements
    licensed(4)
    key = os.environ["AUDITBOX_LICENCE"]
    head, body, sig = key.split(".")
    payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    payload["seats"] = 9999
    forged = head + "." + base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).decode().rstrip("=") + "." + sig
    monkeypatch.setenv("AUDITBOX_LICENCE", forged)
    e = load_entitlements(refresh=True)
    assert e.seats != 9999
    assert not e.frameworks, "a forged licence granted something"
