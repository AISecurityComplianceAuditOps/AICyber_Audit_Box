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

# On top of the model itself: the OS, FastAPI, Redis and the embedding server.
# llm_client.py's auto-start uses the same figure for the same reason.
_FIXED_OVERHEAD_GB = 2.5

# Used only when the model file cannot be measured. It is deliberately the size
# of the SMALLEST shipped model rather than an average: guessing low costs a
# slot, guessing high costs a thrashing server.
_UNKNOWN_MODEL_GB = 4.5

# Default per-request context. Derived pools keep every request at this size no
# matter how many slots exist -- a fixed -c would shrink each slot's share as
# the machine got bigger, starving retrieval on exactly the hardware being sold.
DEFAULT_CTX_PER_REQUEST = 32768

# Global audit cap: roughly one audit per two physical cores, floored so a small
# box still allows a second, capped because past this the model server's own
# batching is the constraint rather than this limit.
_AUDITS_PER_CORES = 2
_MIN_CONCURRENT_AUDITS = 2
_MAX_CONCURRENT_AUDITS = 16

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
    limited_by: str               # "cores" | "ram"

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


def max_concurrent_audits(physical_cores: int) -> int:
    """Global cap on simultaneous audits, from physical cores.

    Slots decide how many audits can START; cores decide whether they FINISH.
    Measured on a 4-physical-core host: three concurrent single-control audits
    were all still running after 900 seconds having completed nothing, while one
    alone takes about five minutes. An honest refusal beats three progress bars
    that never move.
    """
    cores = max(1, int(physical_cores))
    return max(_MIN_CONCURRENT_AUDITS,
               min(_MAX_CONCURRENT_AUDITS, cores // _AUDITS_PER_CORES))


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
    return DeploymentSizing(
        np_slots=slots,
        shared_pool=slots * ctx_per_request,
        ctx_per_request=ctx_per_request,
        max_concurrent_audits=max_concurrent_audits(cores),
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
