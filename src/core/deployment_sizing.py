"""One owner for the deployment sizing arithmetic.

The same numbers -- how many llama.cpp slots, how large the shared KV pool, how
many audits may run at once -- were being derived in two places that disagreed:
run_all.bat computed them in PowerShell at boot, and bg_state.py computed the
audit cap separately in Python. A build-time configurator needs the identical
answer a third time, and three copies of arithmetic drift. They already had:
the launcher reserved a flat 4.5GB for "model and OS" when gemma-4-12B Q8 is
11.8GB, so it handed out slots against roughly 7GB that did not exist, and a
4-core/34GB host running 12B fell to 1.7GB free with prompt processing at
1.82 tok/s -- slower than generation, the signature of paging.

Everything here is a pure function of its arguments. No file reads, no psutil,
no environment: callers supply what they measured, so the same profile can be
sized for a machine nobody is standing in front of. That is what makes it
testable, and what lets the release tool size a customer's bundle from a
hardware profile rather than guessing at install time.
"""
from __future__ import annotations

import math
import os
from dataclasses import dataclass, asdict
from typing import Optional

# ── Constants, carried over verbatim from run_all.bat ────────────────────────
# Per-slot KV cost, 8-bit K and V cache: (ctx / 1024) * 0.12 * 0.5 GB.
_KV_GB_PER_1K_TOKENS = 0.12
_KV_EIGHT_BIT_FACTOR = 0.5

# Of total RAM, what the launcher is willing to plan against. The rest is left
# for the OS and whatever else the operator is running.
_TOTAL_RAM_BUDGET_FRACTION = 0.85

# On top of the model itself: everything else on the machine -- the app (OCR
# and search models loaded), ShaktiDB, Redis, the embedding server and the OS.
# The same figure as the model container's LLM_STACK_RESERVE_GB
# (docker/llm-entrypoint.sh), so what this plans is what the server runs. It
# was 2.5, carried from run_all.bat -- which also sizes from FREE memory, so
# the processes already running are counted there; a container sizing from
# TOTAL memory is not so covered. At 2.5 a 32GB server planned 6 slots, the
# container took 7, and Linux evicted the model weights (measured: a 30-minute
# stall on a GCP VM). At 8: 3 slots on 32GB, 44 on 124GB.
_FIXED_OVERHEAD_GB = 8.0

# Used only when the model file cannot be measured. It is deliberately the size
# of the SMALLEST shipped model rather than an average: guessing low costs a
# slot, guessing high costs a thrashing server.
_UNKNOWN_MODEL_GB = 4.5

# Default per-request context. Derived pools keep every request at this size no
# matter how many slots exist -- a fixed -c would shrink each slot's share as
# the machine got bigger, starving retrieval on exactly the hardware being sold.
DEFAULT_CTX_PER_REQUEST = 32768

# Global audit cap: roughly one audit per two physical cores, floored so a small
# box still allows a second, and bounded by the slots the model server actually
# has rather than by a constant.
#
# There used to be a flat ceiling of 16 here. It was written when a machine had
# about 8 slots, and it silently became the binding limit on hardware that had
# outgrown it: a customer's 32-core/126GB server sized itself to 49 slots and
# was still admitting 16 audits, with no way to tell from the product that the
# number came from a constant rather than from the machine. A appliance sold on
# its hardware should use the hardware it is given.
#
# What replaces it is not "no limit" -- that is worse. Cores decide whether an
# audit FINISHES, and admitting more than the model server has slots for means
# the excess queues inside llama-server, which has no queue limit of its own,
# until each request times out and its control comes back empty. An empty
# control is a missing finding on a compliance report. So the cap is now the
# lower of what the cores can drive and what the server can hold, both measured.
_MIN_CONCURRENT_AUDITS = 2

# How many physical cores one audit needs to make progress. This is the one
# number here that hardware cannot tell us, so it is a measured default rather
# than a derivation: on a 4-physical-core host, three concurrent single-control
# audits (1.33 cores each) were all still running after 900 seconds having
# finished nothing, while one alone takes about five minutes.
#
# That measurement is from a small box, and large machines amortise weight reads
# across batched requests, so the true floor there may be lower. It is a
# parameter, not a constant, precisely so a deployment that has measured its own
# hardware can lower it with evidence instead of editing this file.
DEFAULT_CORES_PER_AUDIT = 2

# Per auditor, so one person cannot occupy the whole machine.
DEFAULT_AUDITS_PER_AUDITOR = 2


@dataclass(frozen=True)
class DeploymentSizing:
    """What a given machine should run, and the figures behind it."""
    # llama-server arguments
    np_slots: int                 # -np
    shared_pool: int              # -c   (np_slots * ctx_per_request)
    ctx_per_request: int

    # application limits
    max_concurrent_audits: int
    max_audits_per_auditor: int

    # the reasoning, kept so a build log or an admin screen can show its work
    physical_cores: int
    total_ram_gb: float
    available_ram_gb: float
    model_gb: float
    kv_gb_per_slot: float
    ram_allowed_slots: int
    projected_llm_gb: float
    headroom_gb: float
    limited_by: str               # slots: "cores" | "ram"
    audits_limited_by: str        # audits: "cores" | "slots" | "floor"
    audit_advice: str             # the sentence shown when an audit is refused

    def as_dict(self) -> dict:
        return asdict(self)

    def llama_server_args(self, model_path: str, threads: int) -> list:
        """The argv llama-server should be launched with for this sizing."""
        return [
            "--port", "11434",
            "-m", model_path,
            "-c", str(self.shared_pool),
            "-np", str(self.np_slots),
            "-t", str(threads),
            "-b", "2048",
            "-ub", "512",
            "--flash-attn", "on",
            "--cont-batching",
            "--kv-unified",
            "-ctk", "q8_0",
            "-ctv", "q8_0",
        ]


def kv_gb_per_slot(ctx_per_request: int = DEFAULT_CTX_PER_REQUEST) -> float:
    """RAM one slot's KV cache occupies at the given per-request context."""
    if ctx_per_request <= 0:
        raise ValueError("ctx_per_request must be positive")
    return (ctx_per_request / 1024.0) * _KV_GB_PER_1K_TOKENS * _KV_EIGHT_BIT_FACTOR


def model_size_gb(model_path: Optional[str]) -> float:
    """Measure the model on disk. Falls back only when it cannot be read.

    Measured, never assumed: the flat 4.5GB this replaces was right for E4B
    (5.1GB) and wrong for gemma-4-12B Q8 (11.8GB) by a factor of two and a half.
    """
    if not model_path:
        return _UNKNOWN_MODEL_GB
    try:
        return os.path.getsize(model_path) / (1024 ** 3)
    except OSError:
        return _UNKNOWN_MODEL_GB


def max_concurrent_audits(physical_cores: int,
                          available_slots: Optional[int] = None,
                          cores_per_audit: int = DEFAULT_CORES_PER_AUDIT) -> int:
    """Global cap on simultaneous audits: the lower of cores and slots.

    Slots decide how many audits can START; cores decide whether they FINISH.
    An honest refusal beats progress bars that never move.

    `available_slots` is the model server's real slot count, read from its
    /slots endpoint. Omitted, the cap comes from cores alone -- the answer for a
    machine being sized before its server exists, and the fallback when the
    probe cannot reach it.
    """
    cores = max(1, int(physical_cores))
    per_audit = max(1, int(cores_per_audit))
    limit = cores // per_audit
    if available_slots is not None and int(available_slots) > 0:
        limit = min(limit, int(available_slots))
    return max(_MIN_CONCURRENT_AUDITS, limit)


def audit_capacity(physical_cores: int,
                   available_slots: Optional[int] = None,
                   cores_per_audit: int = DEFAULT_CORES_PER_AUDIT,
                   slots_limited_by: Optional[str] = None,
                   total_ram_gb: Optional[float] = None) -> dict:
    """The cap, what is holding it there, and what would raise it.

    The product used to refuse an audit with "the system is at capacity (limit
    16)", which tells the customer nothing they can act on: not why 16, not
    whether their machine is the constraint, not what to add. This returns the
    sentence that answers those, so an appliance that has outgrown its hardware
    says so instead of merely saying no.

    `slots_limited_by` is a DeploymentSizing.limited_by value ("cores" or
    "ram"), which distinguishes "add CPU" from "add memory" when the slot count
    is the binding factor rather than the cores.
    """
    cores = max(1, int(physical_cores))
    per_audit = max(1, int(cores_per_audit))
    from_cores = cores // per_audit
    limit = max_concurrent_audits(cores, available_slots, per_audit)

    machine = f"{cores} physical core(s)"
    if total_ram_gb:
        machine += f" and {float(total_ram_gb):.0f}GB RAM"

    if limit <= _MIN_CONCURRENT_AUDITS and from_cores < _MIN_CONCURRENT_AUDITS:
        # The floor is holding it up, not the hardware holding it down.
        return {"limit": limit, "limited_by": "floor",
                "advice": (f"This server has {machine}, below what one audit needs. "
                           f"The minimum of {_MIN_CONCURRENT_AUDITS} is being allowed "
                           f"anyway; expect them to run slowly.")}

    if available_slots is not None and int(available_slots) > 0 and int(available_slots) < from_cores:
        # Slots bind. Say which half of the hardware produced them.
        what = ("more RAM raises it" if slots_limited_by == "ram"
                else "more CPU cores raise it" if slots_limited_by == "cores"
                else "more RAM or CPU cores raise it")
        return {"limit": limit, "limited_by": "slots",
                "advice": (f"This server ({machine}) supports {limit} simultaneous audit(s). "
                           f"The AI engine has {int(available_slots)} slot(s), which is the "
                           f"limiting factor -- {what}.")}

    return {"limit": limit, "limited_by": "cores",
            "advice": (f"This server ({machine}) supports {limit} simultaneous audit(s). "
                       f"CPU cores are the limiting factor at {per_audit} core(s) per audit "
                       f"-- more cores raise it; more RAM will not.")}


def size_deployment(
    physical_cores: int,
    total_ram_gb: float,
    model_path: Optional[str] = None,
    *,
    model_gb: Optional[float] = None,
    available_ram_gb: Optional[float] = None,
    ctx_per_request: int = DEFAULT_CTX_PER_REQUEST,
    max_audits_per_auditor: int = DEFAULT_AUDITS_PER_AUDITOR,
) -> DeploymentSizing:
    """Size a deployment for one machine.

    `model_gb` overrides measurement, so a release tool can size a bundle for a
    model that is not present on the machine doing the building.

    `available_ram_gb` is what is actually free right now. Supplied, the budget
    honours it -- a workstation with an IDE holding 10GB gets fewer slots rather
    than a server that pages. Omitted (the build-time case, where "free" is
    meaningless), only the total is planned against.
    """
    if total_ram_gb <= 0:
        raise ValueError("total_ram_gb must be positive")
    cores = max(1, int(physical_cores))

    resolved_model_gb = model_gb if model_gb is not None else model_size_gb(model_path)
    per_slot = kv_gb_per_slot(ctx_per_request)

    planned = total_ram_gb * _TOTAL_RAM_BUDGET_FRACTION
    budget = min(available_ram_gb, planned) if available_ram_gb is not None else planned
    usable = budget - resolved_model_gb - _FIXED_OVERHEAD_GB
    ram_slots = max(1, math.floor(usable / per_slot)) if usable > 0 else 1

    slots = max(1, min(cores, ram_slots))
    limited_by = "cores" if slots == cores and ram_slots >= cores else "ram"

    projected = resolved_model_gb + (slots * per_slot)
    _cap = audit_capacity(cores, available_slots=slots, slots_limited_by=limited_by,
                          total_ram_gb=total_ram_gb)
    return DeploymentSizing(
        np_slots=slots,
        shared_pool=slots * ctx_per_request,
        ctx_per_request=ctx_per_request,
        max_concurrent_audits=_cap["limit"],
        max_audits_per_auditor=max(1, int(max_audits_per_auditor)),
        physical_cores=cores,
        total_ram_gb=round(total_ram_gb, 2),
        available_ram_gb=round(available_ram_gb, 2) if available_ram_gb is not None else -1.0,
        model_gb=round(resolved_model_gb, 2),
        kv_gb_per_slot=round(per_slot, 3),
        ram_allowed_slots=ram_slots,
        projected_llm_gb=round(projected, 2),
        headroom_gb=round(total_ram_gb - projected, 2),
        limited_by=limited_by,
        audits_limited_by=_cap["limited_by"],
        audit_advice=_cap["advice"],
    )


def size_this_machine(model_path: Optional[str] = None, **kwargs) -> DeploymentSizing:
    """Convenience wrapper: measure the host, then size it.

    The only function here that touches the system, kept apart from the
    arithmetic so the arithmetic stays testable without a machine to measure.

    CALL THIS BEFORE STARTING llama-server, not after. It reads free RAM, and a
    running model server is holding the very memory being planned for -- ask it
    on a box already serving 12B and free RAM reads under a gigabyte, so it
    answers 1 slot for a machine that legitimately supports 4. That is arithmetic
    working correctly on the wrong inputs, and it is why the launcher sizes at
    boot. To size a machine that is already running, stop the server first, or
    pass available_ram_gb explicitly with the server's own usage added back.
    """
    try:
        import psutil
        cores = psutil.cpu_count(logical=False) or psutil.cpu_count() or 4
        mem = psutil.virtual_memory()
        total = mem.total / (1024 ** 3)
        avail = mem.available / (1024 ** 3)
    except Exception:
        cores = os.cpu_count() or 4
        total, avail = 8.0, None
    return size_deployment(cores, total, model_path,
                           available_ram_gb=avail, **kwargs)


if __name__ == "__main__":  # pragma: no cover - operator convenience
    import json
    import sys
    s = size_this_machine(sys.argv[1] if len(sys.argv) > 1 else None)
    print(json.dumps(s.as_dict(), indent=2))
