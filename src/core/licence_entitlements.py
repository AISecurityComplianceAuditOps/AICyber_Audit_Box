"""Which frameworks this installation is licensed to audit.

Separate from endpoints/license.py, which owns the token wallet and expiry and
is left alone. This module answers one question the wallet cannot: *what did
this customer buy?* The wallet counts tokens and dates; it has no field naming
ISO, VAPT or PQC, which is why a PQC-only customer could not be served.

A licence is an Ed25519-signed payload issued by the release tool. Verification
uses only the PUBLIC key, which ships with the product -- so the copy every
customer holds can check a licence but can never mint one. That asymmetry is
the whole mechanism: forging an entitlement requires the private key, which
never leaves the build machine.

ENFORCEMENT IS OPT-IN, and deliberately so. Existing installations have no
entitlement licence at all; enforcing by default would lock every one of them
out on upgrade. So an installation with no licence configured behaves exactly
as it does today and says so once in the log. Customer bundles ship with
AUDITBOX_ENFORCE_ENTITLEMENTS=1, at which point a missing or invalid licence
denies everything rather than allowing it -- fail-closed where it is switched
on, unchanged where it is not.
"""
from __future__ import annotations

import base64
import json
import os
import threading
from dataclasses import dataclass
from datetime import date, datetime
from typing import List, Optional, Set

_SCHEME = "AUDITBOX-LIC-1"

# Where the shipped public key and the customer's licence are found.
ENV_LICENCE = "AUDITBOX_LICENCE"              # the key itself
ENV_LICENCE_FILE = "AUDITBOX_LICENCE_FILE"    # or a path to it
ENV_PUBLIC_KEY_FILE = "AUDITBOX_LICENCE_PUBKEY"
ENV_ENFORCE = "AUDITBOX_ENFORCE_ENTITLEMENTS"

_DEFAULT_PUBKEY = os.path.join("config", "licence_public.pem")
_DEFAULT_LICENCE = os.path.join("data", "licence.key")

_lock = threading.Lock()
_cached: Optional["Entitlements"] = None
_announced = False


class EntitlementError(Exception):
    """Raised when a licensed framework is requested without entitlement."""


@dataclass(frozen=True)
class Entitlements:
    enforcing: bool
    frameworks: Set[str]
    customer: Optional[str] = None
    expires: Optional[date] = None
    reason: str = ""
    # How many audits this site may run at once. None means the licence names no
    # figure, which is every licence issued before seats were enforced -- those
    # installations keep running on hardware capacity alone rather than being
    # retroactively limited by a field nobody had read.
    seats: Optional[int] = None

    def concurrent_limit(self, hardware_limit: int) -> int:
        """The lower of what the hardware can do and what was paid for.

        Both are real limits and neither replaces the other: a licence for
        sixteen simultaneous audits on a four-core box still cannot finish more
        than the box can, and a thirty-two core box may not run more than was
        bought.
        """
        if not self.enforcing or not self.seats:
            return hardware_limit
        return min(hardware_limit, int(self.seats))

    def permits(self, framework: str) -> bool:
        """Whether this installation may audit the named framework.

        Not enforcing means every framework is permitted, which is the state
        every existing installation is in.

        Matching is by normalised token, not equality: the caller may pass a UI
        label ("ISO/IEC 27001:2022"), a stored session value ("PQC Framework
        Controls") or an enum name. Denying a paying customer because of a
        colon would be a worse failure than the one this prevents.
        """
        if not self.enforcing:
            return True
        return _normalise(framework) in self.frameworks


def _normalise(framework: str) -> str:
    """Reduce a framework name to a comparable token.

    "ISO/IEC 27001:2022" -> "ISO27001"      "PQC Framework Controls" -> "PQC"
    "VAPT Framework Controls" -> "VAPT"     "SOC 2" -> "SOC2"
    """
    raw = str(framework or "").upper()
    keep = "".join(ch for ch in raw if ch.isalnum())
    for token in ("ISO27001", "ISO27002", "SOC2", "DPDP", "BCMS", "PQC", "VAPT", "XBOM"):
        if token in keep:
            return token
    if keep.startswith("ISO"):
        return "ISO27001"
    return keep


def _b64u_decode(txt: str) -> bytes:
    return base64.urlsafe_b64decode(txt + "=" * (-len(txt) % 4))


def _read_first(*candidates) -> Optional[str]:
    for value, is_path in candidates:
        if not value:
            continue
        if not is_path:
            return value
        try:
            if os.path.isfile(value):
                with open(value, "r", encoding="utf-8") as fh:
                    text = fh.read().strip()
                if text:
                    return text
        except OSError:
            continue
    return None


def _verify(licence_key: str, public_pem: bytes) -> Entitlements:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization

    parts = licence_key.strip().split(".")
    if len(parts) != 3 or parts[0] != _SCHEME:
        return Entitlements(True, set(), reason="licence key is malformed")

    try:
        body, sig = _b64u_decode(parts[1]), _b64u_decode(parts[2])
        serialization.load_pem_public_key(public_pem).verify(sig, body)
    except InvalidSignature:
        return Entitlements(True, set(),
                            reason="licence signature invalid -- not issued by this vendor")
    except Exception as exc:
        return Entitlements(True, set(), reason=f"licence unreadable: {exc}")

    try:
        payload = json.loads(body)
        expires = date.fromisoformat(payload["expires"])
        frameworks = {_normalise(f) for f in payload["frameworks"]}
        customer = payload.get("customer")
        # Absent, zero or unreadable all mean "no seat limit stated", which is
        # every licence issued before this was enforced. Those keep running on
        # hardware capacity rather than being retroactively capped.
        try:
            seats = int(payload.get("seats") or 0) or None
        except (TypeError, ValueError):
            seats = None
    except (KeyError, ValueError) as exc:
        return Entitlements(True, set(), reason=f"licence payload incomplete: {exc}")

    if expires < date.today():
        return Entitlements(True, set(), customer=customer, expires=expires,
                            reason=f"licence expired on {expires.isoformat()}")

    return Entitlements(True, frameworks, customer=customer, expires=expires,
                        reason="licence verified", seats=seats)


def load_entitlements(refresh: bool = False) -> Entitlements:
    """Resolve this installation's entitlements. Cached; thread-safe.

    Read once because it is consulted on every audit start and every framework
    listing, and a signature check per request would be wasted work on a value
    that changes only when the operator installs a new licence.
    """
    global _cached, _announced
    with _lock:
        if _cached is not None and not refresh:
            return _cached

        enforcing = str(os.environ.get(ENV_ENFORCE, "")).strip().lower() in ("1", "true", "yes", "on")
        if not enforcing:
            ent = Entitlements(False, set(), reason="entitlement enforcement is off")
            if not _announced:
                print("[LICENCE] Entitlement enforcement is OFF -- every framework is "
                      "available. Customer bundles set "
                      f"{ENV_ENFORCE}=1.", flush=True)
                _announced = True
            _cached = ent
            return ent

        licence_key = _read_first(
            (os.environ.get(ENV_LICENCE), False),
            (os.environ.get(ENV_LICENCE_FILE), True),
            (_DEFAULT_LICENCE, True),
        )
        pubkey_path = os.environ.get(ENV_PUBLIC_KEY_FILE) or _DEFAULT_PUBKEY
        try:
            with open(pubkey_path, "rb") as fh:
                public_pem = fh.read()
        except OSError:
            ent = Entitlements(True, set(),
                               reason=f"no verifying key at {pubkey_path}; nothing is licensed")
            _cached = ent
            print(f"[LICENCE] {ent.reason}", flush=True)
            return ent

        if not licence_key:
            ent = Entitlements(True, set(), reason="no licence installed")
        else:
            ent = _verify(licence_key, public_pem)

        _cached = ent
        who = f"{ent.customer}: " if ent.customer else ""
        print(f"[LICENCE] {who}{ent.reason}. "
              f"Permitted: {', '.join(sorted(ent.frameworks)) or 'none'}", flush=True)
        return ent


def permitted_frameworks(all_frameworks: List[str]) -> List[str]:
    """Filter a list of frameworks to those this installation may use."""
    ent = load_entitlements()
    if not ent.enforcing:
        return list(all_frameworks)
    return [f for f in all_frameworks if ent.permits(f)]


def assert_framework_allowed(framework: str) -> None:
    """Raise EntitlementError unless this installation is licensed for it.

    Called server-side at the point an audit starts, not only where the UI
    builds its dropdown: a filtered dropdown is a convenience, while the API is
    the boundary. Anyone can call /audit/start directly.
    """
    ent = load_entitlements()
    if ent.permits(framework):
        return
    licensed = ", ".join(sorted(ent.frameworks)) or "none"
    raise EntitlementError(
        f"This installation is not licensed for {framework}. "
        f"Licensed: {licensed}. {ent.reason}."
    )
