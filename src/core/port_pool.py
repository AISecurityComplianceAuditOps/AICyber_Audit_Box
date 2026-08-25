import os
import sys
import time
import threading
from contextlib import contextmanager

class LLMPortPoolManager:
    """Enterprise LLM Worker Port Pool & Control-Level Mutex Lock Manager.

    Manages pre-warmed LLM worker ports (e.g., 11434, 11435) with per-port mutex locking.
    Provides sub-millisecond (< 1ms) control-level lock release for high-concurrency auditing.

    When all CPU slots are at capacity, incoming requests are queued safely instead of
    being rejected. A CPU_QUEUE_NOTICE system event is emitted and a structured warning
    is published so the UI can display a real-time capacity banner to the auditor.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(LLMPortPoolManager, cls).__new__(cls)
                cls._instance._initialize()
            return cls._instance

    def _initialize(self):
        self._pool_lock = threading.Lock()
        self._rr_index = 0
        # Atomic queue depth counter: tracks how many requests are currently waiting
        # for a semaphore slot across all concurrent threads.
        self._queue_depth = 0
        self._queue_depth_lock = threading.Lock()

        # Determine ports based on environment or hardware CPU count
        hosts_env = os.environ.get("LLM_HOSTS", "").strip()
        if hosts_env:
            raw_ports = [h.strip() for h in hosts_env.split(",") if h.strip()]
            self.ports = []
            for p in raw_ports:
                if p.isdigit():
                    self.ports.append(f"http://127.0.0.1:{p}")
                elif not p.startswith("http"):
                    self.ports.append(f"http://{p}")
                else:
                    self.ports.append(p)
        else:
            # Default completion port is 11434 (11435 is dedicated for embeddings)
            self.ports = ["http://127.0.0.1:11434"]

        # Per-port concurrency limit: caps how many HTTP requests we send to
        # llama-server at once. The server handles its own internal queuing via
        # its -np slots (set in run_all.bat from CPU core count). We use a
        # generous limit here — llama-server queues excess requests internally.
        # The resource guard's check_memory_pressure() is the real crash
        # protector, not this semaphore.
        _slots_per_port = int(os.environ.get("MAX_LLM_CONNECTIONS", "32"))
        self.port_locks = {port: threading.Semaphore(_slots_per_port) for port in self.ports}
        print(f"[PORT POOL INITIALIZED] Configured {len(self.ports)} LLM worker ports: {self.ports} "
              f"({_slots_per_port} max concurrent connections per port)", flush=True)

    def _increment_queue_depth(self):
        """Atomically increments the queue depth counter and returns the new position."""
        with self._queue_depth_lock:
            self._queue_depth += 1
            return self._queue_depth

    def _decrement_queue_depth(self):
        """Atomically decrements the queue depth counter."""
        with self._queue_depth_lock:
            self._queue_depth = max(0, self._queue_depth - 1)

    def get_capacity_snapshot(self, timeout=1.5):
        """Live snapshot of llama-server's real slot busy-ness, queried directly from
        each configured port's own /slots endpoint -- ground truth, not the static
        session-count heuristics used elsewhere. Used at audit start so a user hits
        an honest "all slots busy, you'll be queued" message immediately, instead of
        only discovering it once already deep into a run. Fails open (best-effort,
        never raises) -- this is informational, not a gate.
        """
        import requests
        import concurrent.futures
        total_slots = 0
        busy_slots = 0
        reachable = False

        def _probe(port):
            try:
                r = requests.get(f"{port}/slots", timeout=timeout)
                if r.status_code == 200:
                    slots = r.json() or []
                    return len(slots), sum(1 for s in slots if s.get("is_processing"))
            except Exception:
                pass
            return None

        # Query every configured port concurrently instead of one at a time --
        # previously this added up to N x timeout seconds of pure network latency
        # to the "audit started" response with multiple LLM_HOSTS configured,
        # since each port's own timeout was paid sequentially.
        if self.ports:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.ports)) as executor:
                for result in executor.map(_probe, self.ports):
                    if result is not None:
                        reachable = True
                        t_slots, b_slots = result
                        total_slots += t_slots
                        busy_slots += b_slots
        with self._queue_depth_lock:
            queue_depth = self._queue_depth
        return {
            "reachable": reachable,
            "total_slots": total_slots,
            "busy_slots": busy_slots,
            "queue_depth": queue_depth,
            "at_capacity": bool(reachable and total_slots > 0 and busy_slots >= total_slots),
        }

    @contextmanager
    def acquire_control_slot(self, session_id=None, timeout=None):
        """Context manager leasing a port mutex lock for 1 control query.

        When all CPU slots are busy, the request is safely queued. A CPU_QUEUE_NOTICE
        system event is emitted and a structured warning is published so the UI can
        display a real-time capacity banner (e.g. 'Queued at Position #2, ~30s').

        Yields:
            str: Leased port URL (e.g. 'http://127.0.0.1:11434')
        """
        # Only auto-compute when the caller genuinely didn't specify a timeout.
        # Previously also matched literal 1800/600 as an "auto-compute this"
        # sentinel -- but callers that explicitly pass exactly one of those values
        # (e.g. bg_worker.py's 1800s budget for context-summary/topic-extraction
        # calls) want that literal value honored, not silently overridden. With
        # only 1 active session the adaptive formula recomputes to 600, cutting
        # an explicit 1800s budget by two-thirds precisely when load is lowest.
        if timeout is None:
            try:
                from src.core.redis_metrics import get_live_metrics
                m = get_live_metrics()
                if m.get("redis_available"):
                    active_cnt = max(1, len(m.get("active_sessions", [])))
                else:
                    from src.core.bg_state import _bg_running
                    active_cnt = max(1, len(_bg_running))
                timeout = max(600, active_cnt * 180)
            except Exception:
                timeout = 600

        start_ts = time.time()
        leased_port = None

        # Round-Robin port selection
        with self._pool_lock:
            leased_port = self.ports[self._rr_index % len(self.ports)]
            self._rr_index += 1

        port_lock = self.port_locks[leased_port]

        # Attempt a non-blocking acquire first. If it fails, the slot is at capacity:
        # increment queue depth, log a CPU_QUEUE_NOTICE warning, then block until free.
        queue_position = 0
        is_queued = not port_lock.acquire(blocking=False)
        if is_queued:
            queue_position = self._increment_queue_depth()
            # Estimate wait time: each auditing slot takes ~20s per control on average.
            est_wait_s = queue_position * 20
            queue_msg = (
                f"ℹ️ CPU Capacity Queue Notice: All CPU compute slots are currently processing "
                f"active audits. Your audit has been safely queued in Position #{queue_position} "
                f"and will begin automatically in ~{est_wait_s}s."
            )
            print(f"[PORT POOL] {queue_msg}", flush=True)
            try:
                from src.core.bg_worker import log_system_event
                log_system_event(
                    "CPU_QUEUE_NOTICE",
                    "WARNING",
                    queue_msg,
                    session_id=session_id,
                )
            except Exception:
                pass
            # Live, user-facing version of the same notice: reuses the existing
            # progress["warning"] field that app.js already toasts on (the same
            # mechanism bg_worker.py's static "system busy" notice uses) -- so this
            # reaches the auditor's screen with zero frontend changes.
            if session_id:
                try:
                    from src.core.bg_state import _bg_store, _bg_lock
                    with _bg_lock:
                        _prev = _bg_store["progress"].get(session_id) or {}
                        _bg_store["progress"][session_id] = {
                            **_prev,
                            "warning": (
                                f"⏳ All compute slots busy — you're #{queue_position} in line "
                                f"(~{est_wait_s}s)."
                            ),
                        }
                except Exception:
                    pass
            # Now block until a slot is actually free (respecting timeout)
            acquired = port_lock.acquire(timeout=timeout)
            if not acquired:
                self._decrement_queue_depth()
                try:
                    from src.core.bg_worker import log_system_event
                    log_system_event(
                        "PORT_LOCK_TIMEOUT",
                        "ERROR",
                        f"Failed to acquire port lock on {leased_port} within {timeout}s",
                        session_id=session_id,
                    )
                except Exception:
                    pass
                raise TimeoutError(
                    f"Failed to acquire port lock on {leased_port} within {timeout}s "
                    f"for session {session_id}"
                )

        t_acquire = (time.time() - start_ts) * 1000
        if is_queued:
            print(
                f"[PORT LEASED] Session '{session_id or 'Unknown'}' was queued at position #{queue_position} "
                f"then leased {leased_port} (waited {t_acquire:.0f}ms)",
                flush=True,
            )
            # Slot granted -- clear the queue notice (only our own, never a
            # different warning like the "system busy" or RAM-pressure ones) so the
            # auditor's next poll shows normal progress again instead of a stale
            # "you're in line" message.
            if session_id:
                try:
                    from src.core.bg_state import _bg_store, _bg_lock
                    with _bg_lock:
                        _prev = _bg_store["progress"].get(session_id) or {}
                        if str(_prev.get("warning") or "").startswith("⏳ All compute slots busy"):
                            _bg_store["progress"][session_id] = {**_prev, "warning": None}
                except Exception:
                    pass
        else:
            print(
                f"[PORT LEASED] Session '{session_id or 'Unknown'}' leased {leased_port} "
                f"(Lock acquired in {t_acquire:.2f}ms)",
                flush=True,
            )

        try:
            yield leased_port
        finally:
            if is_queued:
                self._decrement_queue_depth()
            rel_start = time.time()
            port_lock.release()
            t_release = (time.time() - rel_start) * 1000
            print(
                f"[PORT RELEASED] Session '{session_id or 'Unknown'}' released {leased_port} "
                f"(Sub-ms release: {t_release:.3f}ms)",
                flush=True,
            )

# Singleton global instance
port_pool_manager = LLMPortPoolManager()

