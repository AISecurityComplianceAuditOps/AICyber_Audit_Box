import os
import sys
import time
import threading
from contextlib import contextmanager

class LLMPortPoolManager:
    # Probing for the server's slot count: how many times, and how far apart.
    # Sized from the measured worst case -- the 12B model answers 503 for about
    # 41 seconds while loading -- with room to spare, and bounded so an absent
    # server costs at most this many 5-second timeouts in total.
    _LIMIT_MAX_ATTEMPTS = 12
    _LIMIT_RETRY_AFTER_SEC = 20.0

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
        _env_limit = os.environ.get("MAX_LLM_CONNECTIONS")
        _slots_per_port = int(_env_limit) if _env_limit else 32
        self.port_locks = {port: threading.Semaphore(_slots_per_port) for port in self.ports}

        # The default of 32 is a guess made before the server exists, and on a
        # large machine it is the binding constraint rather than a generous one:
        # measured on a customer box, llama-server sized itself to 49 slots from
        # 125.64GB and 64 cores while this capped the app at 32, leaving a third
        # of the hardware idle and queueing users who did not need to wait.
        #
        # The real number cannot be read here. This runs at import, when the LLM
        # container is still loading 12.7GB of weights, so /slots would not
        # answer and every probe would fall back to the same guess. It is read
        # once instead, on the first acquire, by which time the server is up.
        #
        # An explicit MAX_LLM_CONNECTIONS is an operator decision and is never
        # second-guessed.
        self._limit_per_port = _slots_per_port
        self._limit_is_explicit = bool(_env_limit)
        self._limit_checked = False
        self._limit_attempts = 0
        self._limit_last_attempt = 0.0
        self._limit_lock = threading.Lock()
        # The server's real slot count once known, or None. Recorded even when
        # an explicit limit means we do not act on it, because the audit
        # admission cap is sized from this number too and an operator capping
        # connections did not ask to distort the machine's stated capacity.
        self._server_slot_count = None

        print(f"[PORT POOL INITIALIZED] Configured {len(self.ports)} LLM worker ports: {self.ports} "
              f"({_slots_per_port} max concurrent connections per port"
              f"{'' if _env_limit else ', pending the server\'s own slot count'})", flush=True)

    def _match_server_slot_count(self):
        """Raise the per-port limit to the server's slot count, once.

        Only ever upward: a Semaphore's capacity grows by releasing extra
        permits, and lowering it would strand requests already holding one. If
        the server answers with fewer slots than we assumed, its own internal
        queue handles the excess, which is what it did before this existed.

        One port is asked and the answer applied to all of them: every
        llama-server comes from the same entrypoint and sizes itself from the
        same hardware. A host that happens to have fewer slots falls back to
        that same internal queue.

        RETRIED, because the usual reason for failure is temporary. Measured on
        this machine: while llama-server loads its weights, /slots answers

            HTTP 503  {"error":{"message":"Loading model",...}}

        for 41 seconds with the 12B model. An audit started in that window is
        exactly when a first probe happens, and a single attempt would mark the
        count unknowable for the life of the process -- the app would sit at its
        default for hours after the server was ready, with nothing to show the
        measurement had been skipped. Attempts are capped and spaced so a
        genuinely absent server costs a bounded number of short timeouts rather
        than one per request.
        """
        if self._limit_checked:
            return
        with self._limit_lock:
            if self._limit_checked:
                return
            now = time.time()
            if self._limit_attempts >= self._LIMIT_MAX_ATTEMPTS:
                self._limit_checked = True      # give up, quietly and for good
                return
            if now - self._limit_last_attempt < self._LIMIT_RETRY_AFTER_SEC:
                return                          # too soon; try on a later call
            self._limit_attempts += 1
            self._limit_last_attempt = now
            try:
                # Imported here, as get_capacity_snapshot does: this module is
                # imported during startup and must not depend on requests being
                # importable at that moment.
                import requests
                r = requests.get(f"{self.ports[0]}/slots", timeout=5)
                if r.status_code != 200:
                    # 503 "Loading model" lands here. Not an answer, so not
                    # final: the attempt counter above bounds the retrying.
                    return
                payload = r.json()
                if not isinstance(payload, list):
                    # While loading, the body is an error OBJECT. len() of a
                    # dict counts its keys, so treating it as slots would read
                    # {"error": {...}} as one slot and cap the whole appliance.
                    return
                server_slots = len(payload)
                if server_slots <= 0:
                    return
                self._server_slot_count = server_slots
                self._limit_checked = True      # a real answer; stop asking
            except Exception as e:
                print(f"[PORT POOL] Could not read the server's slot count "
                      f"({type(e).__name__}, attempt {self._limit_attempts} of "
                      f"{self._LIMIT_MAX_ATTEMPTS}); staying at "
                      f"{self._limit_per_port} per port.", flush=True)
                return
            if self._limit_is_explicit:
                return                          # operator's number; only recorded
            extra = server_slots - self._limit_per_port
            if extra <= 0:
                return
            for lock in self.port_locks.values():
                for _ in range(extra):
                    lock.release()
            old = self._limit_per_port
            self._limit_per_port = server_slots
            print(f"[PORT POOL] LLM server reports {server_slots} slot(s); raising the "
                  f"per-port limit from {old} to {server_slots}. Set "
                  f"MAX_LLM_CONNECTIONS to override.", flush=True)

    def known_slot_count(self):
        """The model server's real slot count, or None if it could not be read.

        Shares the one-time probe that sizes the semaphore, so asking costs
        nothing after the first call. Callers use it to derive limits from what
        the machine actually has instead of from a constant -- the audit
        admission cap is the one that matters, since admitting more audits than
        there are slots pushes the excess into llama-server's own unbounded
        queue, where requests time out and their controls come back empty.

        None means "could not find out", which callers must treat as unknown
        rather than as zero: falling back to a cores-only figure is the old
        behaviour and is safe, while reading None as no capacity would refuse
        every audit on a server that is merely slow to answer.
        """
        self._match_server_slot_count()
        return self._server_slot_count

    def _increment_queue_depth(self):
        """Atomically increments the queue depth counter and returns the new position."""
        with self._queue_depth_lock:
            self._queue_depth += 1
            return self._queue_depth

    def _decrement_queue_depth(self):
        """Atomically decrements the queue depth counter."""
        with self._queue_depth_lock:
            self._queue_depth = max(0, self._queue_depth - 1)

    def get_capacity_snapshot(self, timeout=3.0):
        """Live snapshot of llama-server's real slot busy-ness, queried directly from
        each configured port's own /slots endpoint -- ground truth, not the static
        session-count heuristics used elsewhere. Used at audit start so a user hits
        an honest "all slots busy, you'll be queued" message immediately, instead of
        only discovering it once already deep into a run. Never raises.

        llama-server answers /slots from the same threads that run inference, so
        the probe is SLOWEST exactly when every slot is busy -- the moment the
        answer matters most. At the old 1.5s timeout it simply timed out under
        load and returned reachable=False / total_slots=0, which made
        at_capacity compute to False: the snapshot claimed free capacity
        precisely when there was none, and the "you'll be queued" banner never
        appeared.

        The timeout stays short on purpose -- this sits in the audit-start path,
        and a saturated llama-server may not answer at all however long we wait
        (measured: still silent at 6s under load). So the honest signal is
        `probe_failed`, which distinguishes "we could not find out" from the
        zeroed counters that otherwise read as "idle".
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
            # True when the server is configured but did not answer in time. The
            # caller can tell "idle" apart from "we could not find out", which
            # the zeroed counters above cannot express on their own.
            "probe_failed": bool(self.ports) and not reachable,
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

        # First use: the LLM is up by now, so ask how many slots it really has.
        self._match_server_slot_count()

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

