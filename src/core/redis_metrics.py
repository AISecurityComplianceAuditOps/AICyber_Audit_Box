"""
redis_metrics.py
─────────────────────────────────────────────────────────────────────────────
Redis Live Metrics Helper for AICyberAuditBox Admin Dashboard.

Stores per-session and global telemetry in Redis so the
"Live Server Metrics (Redis Stream)" KPI panel is truly real-time.

Key schema
──────────
  session:{sid}:tokens        INCRBY    total tokens for this session
  session:{sid}:prompt_tokens INCRBY
  session:{sid}:comp_tokens   INCRBY
  session:{sid}:latency_sec   INCRBYFLOAT  cumulative latency seconds
  session:{sid}:files         SET       file count (integer)
  session:{sid}:file_mb       SET       total file size MB (float string)
  session:{sid}:controls      INCRBY    controls evaluated count
  session:{sid}:errors        INCRBY    error/warning count
  session:{sid}:auditor       SET       auditor username
  session:{sid}:status        SET       "running" | "done" | "error"
  session:{sid}:started_at    SET       ISO timestamp
  session:{sid}:updated_at    SET       ISO timestamp (updated on each write)

  global:tokens               INCRBY    grand total tokens across all sessions
  global:latency_sec          INCRBYFLOAT
  global:files                INCRBY
  global:errors               INCRBY
  global:active_sessions      SADD/SREM   native Redis Set of active session ids
  global:completed_sessions   LPUSH/LTRIM native Redis List, newest-first, capped at 50

TTL: each session key expires after 24 hours automatically.
Falls back silently to no-op if Redis is not reachable.
"""

import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SESSION_TTL = 86400   # 24 hours

_redis_client = None
_redis_available = False


def _get_redis():
    """Lazy-init Redis client with dual-port fallback (6380 / 6379) and auto-reconnect."""
    global _redis_client, _redis_available
    if _redis_client is not None and _redis_available:
        try:
            _redis_client.ping()
            return _redis_client
        except Exception:
            _redis_available = False
            _redis_client = None

    try:
        import redis
        urls_to_try = [
            os.environ.get("REDIS_URL", "redis://127.0.0.1:6380/0"),
            "redis://127.0.0.1:6379/0",
            "redis://127.0.0.1:6380/0"
        ]
        seen = set()
        urls = [u for u in urls_to_try if not (u in seen or seen.add(u))]

        for url in urls:
            try:
                client = redis.from_url(url, decode_responses=True, protocol=2, socket_timeout=1, socket_connect_timeout=1)
                client.ping()
                _redis_client = client
                _redis_available = True
                logger.info(f"[Redis] Connected to {url}")
                return _redis_client
            except Exception:
                continue
    except Exception as e:
        logger.warning(f"[Redis] Import or connection check failed: {e}")

    _redis_available = False
    _redis_client = None
    return None



def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def session_start(session_id: str, auditor: str = "SYSTEM", files_count: int = 0, file_mb: float = 0.0):
    """
    Called when an audit session starts.
    Registers the session as 'running' in Redis and adds it to global:active_sessions.
    """
    r = _get_redis()
    if not r:
        return
    try:
        pipe = r.pipeline()
        prefix = f"session:{session_id}"
        pipe.set(f"{prefix}:auditor",    auditor)
        pipe.set(f"{prefix}:status",     "running")
        pipe.set(f"{prefix}:started_at", _ts())
        pipe.set(f"{prefix}:updated_at", _ts())
        pipe.set(f"{prefix}:files",      str(files_count))
        pipe.set(f"{prefix}:file_mb",    str(round(file_mb, 3)))
        pipe.set(f"{prefix}:tokens",     "0")
        pipe.set(f"{prefix}:prompt_tokens", "0")
        pipe.set(f"{prefix}:comp_tokens",   "0")
        pipe.set(f"{prefix}:latency_sec",   "0")
        pipe.set(f"{prefix}:controls",      "0")
        pipe.set(f"{prefix}:errors",        "0")
        for key in [
            f"{prefix}:auditor", f"{prefix}:status", f"{prefix}:started_at",
            f"{prefix}:updated_at", f"{prefix}:files", f"{prefix}:file_mb",
            f"{prefix}:tokens", f"{prefix}:prompt_tokens", f"{prefix}:comp_tokens",
            f"{prefix}:latency_sec", f"{prefix}:controls", f"{prefix}:errors",
        ]:
            pipe.expire(key, SESSION_TTL)

        # Native Redis SET (SADD) — atomic, no read-modify-write race between
        # concurrent sessions starting/finishing at the same time.
        pipe.sadd("global:active_sessions", session_id)
        pipe.expire("global:active_sessions", SESSION_TTL)
        pipe.incrby("global:files", files_count)
        pipe.expire("global:files", SESSION_TTL)
        pipe.execute()
    except Exception as e:
        logger.warning(f"[Redis] session_start failed: {e}")


def push_control_metrics(session_id: str, prompt_tokens: int, comp_tokens: int, latency_sec: float):
    """
    Called after EACH control is evaluated in bg_worker.py.
    Atomically increments per-session AND global Redis counters.
    """
    r = _get_redis()
    if not r:
        return
    try:
        total_tokens = prompt_tokens + comp_tokens
        pipe = r.pipeline()
        prefix = f"session:{session_id}"
        pipe.incrby(f"{prefix}:tokens",        total_tokens)
        pipe.incrby(f"{prefix}:prompt_tokens", prompt_tokens)
        pipe.incrby(f"{prefix}:comp_tokens",   comp_tokens)
        pipe.incrbyfloat(f"{prefix}:latency_sec", latency_sec)
        pipe.incrby(f"{prefix}:controls", 1)
        pipe.set(f"{prefix}:updated_at", _ts())
        for key in [
            f"{prefix}:tokens", f"{prefix}:prompt_tokens", f"{prefix}:comp_tokens",
            f"{prefix}:latency_sec", f"{prefix}:controls", f"{prefix}:updated_at",
        ]:
            pipe.expire(key, SESSION_TTL)
        pipe.incrby("global:tokens", total_tokens)
        pipe.incrbyfloat("global:latency_sec", latency_sec)
        pipe.expire("global:tokens", SESSION_TTL)
        pipe.expire("global:latency_sec", SESSION_TTL)
        pipe.execute()
    except Exception as e:
        logger.warning(f"[Redis] push_control_metrics failed: {e}")


def push_error(session_id: str):
    """Increment error counter for this session and globally."""
    r = _get_redis()
    if not r:
        return
    try:
        pipe = r.pipeline()
        pipe.incrby(f"session:{session_id}:errors", 1)
        pipe.expire(f"session:{session_id}:errors", SESSION_TTL)
        pipe.incrby("global:errors", 1)
        pipe.expire("global:errors", SESSION_TTL)
        pipe.execute()
    except Exception as e:
        logger.warning(f"[Redis] push_error failed: {e}")


def session_done(session_id: str, status: str = "done"):
    """Mark session as done/error. Moves from active_sessions to completed_sessions.
    Keeps completed sessions visible in admin for SESSION_TTL seconds."""
    r = _get_redis()
    if not r:
        return
    try:
        pipe = r.pipeline()
        pipe.set(f"session:{session_id}:status",     status)
        pipe.set(f"session:{session_id}:updated_at", _ts())
        pipe.expire(f"session:{session_id}:status",     SESSION_TTL)
        pipe.expire(f"session:{session_id}:updated_at", SESSION_TTL)

        # Move from active -> completed (do NOT delete — admin must still see it).
        # Native atomic Redis ops: SREM needs no prior read, and LREM+LPUSH+LTRIM
        # dedups/prepends/caps the completed list without a read-modify-write race.
        pipe.srem("global:active_sessions", session_id)
        pipe.expire("global:active_sessions", SESSION_TTL)

        pipe.lrem("global:completed_sessions", 0, session_id)
        pipe.lpush("global:completed_sessions", session_id)
        pipe.ltrim("global:completed_sessions", 0, 49)  # keep newest 50
        pipe.expire("global:completed_sessions", SESSION_TTL)
        pipe.execute()
    except Exception as e:
        logger.warning(f"[Redis] session_done failed: {e}")


def get_live_metrics(limit: int = 500) -> dict:
    """
    Read all live metrics from Redis for the Admin Dashboard KPI panel.
    Returns a dict with global totals and per-session active session details.
    Falls back to empty/zero values if Redis is not available.
    """
    r = _get_redis()
    if not r:
        db_sessions = _fetch_db_completed_sessions(set(), limit=limit)
        return {
            "redis_available": False,
            "global_tokens": sum(s["tokens"] for s in db_sessions),
            "global_latency_sec": 0.0,
            "global_latency_str": "0m 0.0s",
            "avg_latency_per_ctrl_str": "0m 0.0s",
            "global_files": sum(s["files"] for s in db_sessions),
            "global_errors": 0,
            "active_sessions": db_sessions
        }
    try:
        global_tokens  = int(r.get("global:tokens") or 0)
        global_latency = float(r.get("global:latency_sec") or 0.0)
        global_files   = int(r.get("global:files") or 0)
        global_errors  = int(r.get("global:errors") or 0)

        active_ids = r.smembers("global:active_sessions") or set()

        # ── Build session rows: active first, then completed ──────────────────
        sessions = []
        seen_sids = set()

        def _build_session_row(sid):
            if sid in seen_sids:
                return None
            seen_sids.add(sid)
            status     = r.get(f"session:{sid}:status") or "unknown"
            auditor    = r.get(f"session:{sid}:auditor") or "SYSTEM"
            tokens     = int(r.get(f"session:{sid}:tokens") or 0)
            latency    = float(r.get(f"session:{sid}:latency_sec") or 0.0)
            files      = int(r.get(f"session:{sid}:files") or 0)
            file_mb    = float(r.get(f"session:{sid}:file_mb") or 0.0)
            controls   = int(r.get(f"session:{sid}:controls") or 0)
            errors     = int(r.get(f"session:{sid}:errors") or 0)
            updated_at = r.get(f"session:{sid}:updated_at") or ""
            started_at = r.get(f"session:{sid}:started_at") or ""
            mins = int(latency // 60); secs = round(latency % 60, 1)
            lat_str = f"{mins}m {secs}s" if mins > 0 else f"0m {secs}s"
            return {
                "session_id":  sid,
                "auditor":     auditor,
                "status":      status,
                "tokens":      tokens,
                "latency_sec": round(latency, 1),
                "latency_str": lat_str,
                "files":       files,
                "file_mb":     round(file_mb, 2),
                "controls":    controls,
                "errors":      errors,
                "updated_at":  updated_at,
                "started_at":  started_at,
                "is_estimated": False,  # a real key was read from Redis, not reconstructed
            }

        # Active sessions first
        for sid in active_ids:
            row = _build_session_row(sid)
            if row:
                sessions.append(row)

        # Completed sessions — LPUSH prepends, so LRANGE already returns newest first.
        done_ids = r.lrange("global:completed_sessions", 0, limit - 1) or []
        for sid in done_ids:
            row = _build_session_row(sid)
            if row:
                sessions.append(row)

        # ── DB Fallback: Load saved AuditReports if Redis has no completed sessions ──
        if len(sessions) < limit:
            db_sessions = _fetch_db_completed_sessions(seen_sids, limit=limit - len(sessions))
            sessions.extend(db_sessions)

        # Sort: running first, then done by updated_at descending
        def _sort_key(s):
            order = 0 if s["status"] == "running" else (1 if s["status"] == "done" else 2)
            return (order, s.get("updated_at", ""))
        sessions.sort(key=_sort_key)

        g_mins = int(global_latency // 60); g_secs = round(global_latency % 60, 1)
        g_lat_str = f"{g_mins}m {g_secs}s" if g_mins > 0 else f"0m {g_secs}s"
        total_controls = sum(s["controls"] for s in sessions) or 1
        avg_lat = global_latency / max(1, total_controls)
        avg_mins = int(avg_lat // 60); avg_secs = round(avg_lat % 60, 1)
        avg_lat_str = f"{avg_mins}m {avg_secs}s" if avg_mins > 0 else f"0m {avg_secs}s"

        return {
            "redis_available": True,
            "global_tokens":              global_tokens or (sum(s["tokens"] for s in sessions)),
            "global_latency_sec":         round(global_latency, 1),
            "global_latency_str":         g_lat_str,
            "avg_latency_per_ctrl_str":   avg_lat_str,
            "global_files":               global_files or (sum(s["files"] for s in sessions)),
            "global_errors":              global_errors,
            "active_sessions":            sessions,
        }
    except Exception as e:
        logger.warning(f"[Redis] get_live_metrics failed: {e}")
        db_sessions = _fetch_db_completed_sessions(set(), limit=limit)
        return {
            "redis_available": False,
            "global_tokens": sum(s["tokens"] for s in db_sessions),
            "global_latency_sec": 0.0,
            "global_latency_str": "0m 0.0s",
            "avg_latency_per_ctrl_str": "0m 0.0s",
            "global_files": sum(s["files"] for s in db_sessions),
            "global_errors": 0,
            "active_sessions": db_sessions
        }


def get_running_session_count() -> int:
    """
    Counts audits that are GENUINELY running right now, not the mixed
    running+recently-done list get_live_metrics() returns for the admin
    dashboard's display. Shared by the adaptive timeout (audit_graph.py) and
    the "system busy" warning (bg_worker.py) so both use one tested source of
    truth instead of duplicating the Redis-vs-in-memory fallback logic.

    Falls back to the in-memory _bg_running set if Redis is unavailable.
    """
    try:
        m = get_live_metrics()
        if m.get("redis_available"):
            running = [s for s in m.get("active_sessions", []) if s.get("status") == "running"]
            return len(running)
    except Exception:
        pass
    try:
        from src.core.bg_state import _bg_running
        return len(_bg_running)
    except Exception:
        return 0


def _fetch_db_completed_sessions(seen_sids: set, limit: int = 500) -> list:
    """Helper to query completed AuditReports from ShaktiDB / SQLite when Redis buffer is empty."""
    db_rows = []
    try:
        from src.db.database import SessionLocal, AuditReport, Finding, EvidenceFile
        db = SessionLocal()
        try:
            reports = db.query(AuditReport).order_by(AuditReport.created_at.desc()).limit(limit * 2).all()
            for r in reports:
                if not r.session_id or r.session_id in seen_sids:
                    continue
                seen_sids.add(r.session_id)
                findings_cnt = db.query(Finding).filter(Finding.report_id == r.id).count() or 1
                files_cnt = db.query(EvidenceFile).filter(EvidenceFile.report_id == r.id).count() or 1
                status = "done"
                created_str = r.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if r.created_at else _ts()
                # tokens/latency_sec here are a rough per-finding placeholder formula
                # (350 tok, 1.5s), NOT a measured value -- this branch only runs when
                # Redis has no key for the session (unreachable, or its 24h TTL already
                # expired), so the real push_control_metrics() numbers are gone. Tagged
                # is_estimated=True so callers/UI never present this as real telemetry.
                db_rows.append({
                    "session_id":  r.session_id,
                    "auditor":     r.created_by or r.assigned_auditor_username or "Auditor",
                    "status":      status,
                    "tokens":      findings_cnt * 350,
                    "latency_sec": round(findings_cnt * 1.5, 1),
                    "latency_str": f"{int(findings_cnt*1.5//60)}m {round(findings_cnt*1.5%60, 1)}s",
                    "files":       files_cnt,
                    "file_mb":     0.5,
                    "controls":    findings_cnt,
                    "errors":      0,
                    "updated_at":  created_str,
                    "started_at":  created_str,
                    "is_estimated": True,
                })
                if len(db_rows) >= limit:
                    break
        finally:
            db.close()
    except Exception as db_err:
        logger.warning(f"[Redis] _fetch_db_completed_sessions failed: {db_err}")
    return db_rows


