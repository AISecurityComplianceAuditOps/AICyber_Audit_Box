"""How many model requests one scan may have in flight at a time.

The model server's slot count is the machine's real capacity: run_all.bat and
deployment_sizing size it from physical cores and free RAM when the server
starts. A scan that sends more requests than its share of those slots only
makes every request slower -- on a small CPU, slow enough to fail -- so each
scan takes a fair share instead:

    usable = slots - 1 on a machine with 4 physical cores or fewer, else slots
    share  = max(1, usable // scans using the model right now)

Recomputed by the caller after every request, so a scan grows into slots that
another one releases and shrinks when a new one starts.
"""
import os
import threading
from contextlib import contextmanager

_active = {}
_active_lock = threading.Lock()


@contextmanager
def scan_using_llm(key):
    """Count this scan as using the model while the block runs."""
    key = str(key)
    with _active_lock:
        _active[key] = _active.get(key, 0) + 1
    try:
        yield
    finally:
        with _active_lock:
            _active[key] -= 1
            if _active[key] <= 0:
                del _active[key]


def active_scans():
    with _active_lock:
        return len(_active)


def _physical_cores():
    try:
        from src.core.bg_state import _physical_cores as _pc
        return int(_pc())
    except Exception:
        return max(1, (os.cpu_count() or 4) // 2)


def model_slots():
    """The model server's slot count.

    LLM_SLOTS first: run_all.bat sets it to the -np it starts llama-server
    with, and an operator may set it explicitly. Otherwise the server's own
    /slots answer; failing that, the physical core count (what run_all.bat
    would have chosen without the RAM check)."""
    env = os.environ.get("LLM_SLOTS", "").strip()
    if env.isdigit() and int(env) > 0:
        return int(env)
    try:
        from src.core.port_pool import port_pool_manager
        n = port_pool_manager.known_slot_count()
        if n:
            return int(n)
    except Exception:
        pass
    return _physical_cores()


def usable_slots(slots=None, cores=None):
    slots = model_slots() if slots is None else int(slots)
    cores = _physical_cores() if cores is None else int(cores)
    # One kept free on a small machine for everything else that needs the
    # model meanwhile: another auditor's control, the chat assistant.
    return max(1, slots - 1) if cores <= 4 and slots > 1 else max(1, slots)


def fair_share(slots=None, cores=None, scans=None):
    scans = active_scans() if scans is None else int(scans)
    return max(1, usable_slots(slots, cores) // max(1, scans))
