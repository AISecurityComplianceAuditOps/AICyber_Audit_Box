import threading
from collections import defaultdict

def _get_bg_store():
    if not hasattr(_get_bg_store, "_instance"):
        _get_bg_store._instance = {
            "results": {},
            "running": set(),
            "progress": {},
            "lock": threading.Lock(),
            "summaries": {}
        }
    return _get_bg_store._instance

_bg_store = _get_bg_store()
_bg_results = _bg_store["results"]
_bg_running = _bg_store["running"]
_bg_lock = _bg_store["lock"]

# Stop flags: bg_key -> True means "please stop this scan"
_bg_stop_flags: dict = {}

# Per-auditor session tracking: auditor_id -> set of active session_ids
# Limits how many concurrent audits one auditor can run simultaneously.
# The resource guard (src/core/resource_guard.py) is the real RAM safety net --
# this exists to stop accidental pile-up (double-clicks, multiple tabs) rather
# than to be a hard resource budget, so it's kept low.
_auditor_sessions: dict = defaultdict(set)  # {auditor_id: {session_id, ...}}
MAX_AUDITS_PER_AUDITOR = int(__import__('os').environ.get("MAX_AUDITS_PER_AUDITOR", "2"))

# Global cap across ALL auditors combined -- was previously set as an env var
# in run_all.bat (MAX_CONCURRENT_AUDITS) but never actually read anywhere, so
# it did nothing. llama-server's own request queue (via --cont-batching) has
# no size limit of its own: past LLM_SLOTS truly-parallel slots, every
# further request just queues silently with growing wait times, and a
# client's own request timeout can fire before its turn ever comes. This is
# the real backstop -- reject the (LLM_SLOTS*2 + 1)th+ request at the API
# level with a clear "system busy" message instead of letting it queue
# indefinitely toward a confusing timeout. Default of 16 assumes 8 LLM_SLOTS
# (8 truly concurrent + 8 queued as buffer); adjust if LLM_SLOTS changes.
def _default_concurrent_audits() -> int:
    """Global audit cap, sized from the machine's PHYSICAL cores.

    A fixed 16 was a guess about the hardware, and on a small box it admits far
    more work than the machine can finish. Measured on a 4-physical-core host:
    three concurrent single-control Quick audits were all still running after 900
    seconds, having completed nothing, while one audit alone takes about five
    minutes. They were not stuck -- they were sharing four cores between three
    llama.cpp workers, so each ran several times slower.

    That is the failure this default exists to prevent, and it is worse than a
    refusal: every audit is admitted, the interface shows them all "running", and
    no result arrives. An honest "system at capacity" is better than a progress
    bar that never moves.

    Slots decide how many audits can START; cores decide whether they FINISH.
    Roughly one audit per two physical cores keeps each one responsive, floored
    at 2 so a small box still allows a second audit.

    The arithmetic itself lives in deployment_sizing, which is its one owner.
    This used to hold a second, independent copy of the same formula. The two
    agreed, but nothing held them together, and nothing outside that module
    called its version -- so the figure the product enforced and the figure a
    build log reported were free to drift apart while looking authoritative.

    This value is the STARTING point only, from cores alone: it is computed at
    import, when the model server is still loading its weights and cannot say
    how many slots it has. current_audit_limit() refines it once the server can
    answer. Anything admitting work should call that, not read this.

    MAX_CONCURRENT_AUDITS in the environment always wins -- an operator who has
    measured their own hardware should override this.
    """
    import os
    env = os.environ.get("MAX_CONCURRENT_AUDITS")
    if env and str(env).strip().isdigit():
        return int(env)
    try:
        import psutil
        physical = psutil.cpu_count(logical=False) or psutil.cpu_count() or 4
    except Exception:
        physical = os.cpu_count() or 4
    from src.core.deployment_sizing import max_concurrent_audits
    return max_concurrent_audits(physical, cores_per_audit=_cores_per_audit())


def _cores_per_audit() -> int:
    """Physical cores one audit needs, overridable by an operator who measured.

    The default is a measurement from a small host and deliberately a parameter
    rather than a constant: a deployment that has load-tested its own hardware
    should be able to lower it on evidence without a code change.
    """
    import os
    from src.core.deployment_sizing import DEFAULT_CORES_PER_AUDIT
    env = os.environ.get("CORES_PER_AUDIT")
    if env and str(env).strip().isdigit() and int(env) > 0:
        return int(env)
    return DEFAULT_CORES_PER_AUDIT


def _physical_cores() -> int:
    import os
    try:
        import psutil
        return psutil.cpu_count(logical=False) or psutil.cpu_count() or 4
    except Exception:
        return os.cpu_count() or 4


def _total_ram_gb():
    """Total memory, for describing the machine. None if it cannot be read."""
    try:
        import psutil
        return psutil.virtual_memory().total / (1024.0 ** 3)
    except Exception:
        return None


def current_audit_limit() -> tuple:
    """(limit, advice) for right now, sized from the live machine.

    Returns the cap to admit against and the sentence explaining what is holding
    it there, so a refusal can tell the customer what to add instead of only
    saying no.

    Why this is a function and not the constant above: the real slot count can
    only be read once the model server is up, which it is not at import. The
    first call after that learns it, and the port pool caches it, so the cost is
    one probe for the life of the process.

    An explicit MAX_CONCURRENT_AUDITS is an operator's decision and is returned
    unchanged -- the hardware is still described in the advice, so an operator
    who has pinned a number below what the machine can do can see that they did.
    """
    import os
    env = os.environ.get("MAX_CONCURRENT_AUDITS")
    cores = _physical_cores()
    per_audit = _cores_per_audit()

    slots = None
    try:
        from src.core.port_pool import port_pool_manager
        slots = port_pool_manager.known_slot_count()
    except Exception:
        # Never let sizing take audits down; cores alone is the old behaviour.
        slots = None

    from src.core.deployment_sizing import audit_capacity
    cap = audit_capacity(cores, available_slots=slots, cores_per_audit=per_audit,
                         total_ram_gb=_total_ram_gb())
    if env and str(env).strip().isdigit():
        pinned = int(env)
        return pinned, (f"This installation is pinned to {pinned} simultaneous audit(s) "
                        f"by MAX_CONCURRENT_AUDITS. {cap['advice']}")
    return cap["limit"], cap["advice"]


MAX_CONCURRENT_AUDITS = _default_concurrent_audits()
