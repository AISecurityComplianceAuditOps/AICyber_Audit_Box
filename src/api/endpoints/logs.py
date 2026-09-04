from fastapi import APIRouter, HTTPException, Query, Request
from typing import Optional
import os
from src.db.database import (
    SessionLocal,
    SystemEvent,
    AuditTrail,
    purge_old_logs,
    force_master
)
from src.api.endpoints.auth import _require_auth

router = APIRouter(prefix="/logs", tags=["Admin Logs"])

LOG_PATH = "data/audit_run_latency.log"

@router.get("/system")
def api_get_system_events(
    request: Request,
    severity: str = Query("All", description="Filter by severity level"),
    event_type: str = Query("", description="Filter by event type substring"),
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    actor: Optional[str] = Query(None, description="Filter by auditor username or actor"),
    page: int = Query(0, ge=0),
    page_size: int = Query(20, ge=1, le=100)
):
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    db = SessionLocal()
    try:
        query = db.query(SystemEvent)
        if severity and severity != "All":
            query = query.filter(SystemEvent.severity == severity)
        if event_type and event_type.strip():
            query = query.filter(SystemEvent.event_type.ilike(f"%{event_type.strip()}%"))
        if session_id and session_id.lower() not in ("all", "active"):
            query = query.filter(SystemEvent.session_id == session_id)
        if actor and actor.strip() and actor.lower() != "all":
            query = query.filter(SystemEvent.actor.ilike(f"%{actor.strip()}%"))
        
        total_count = query.count()
        rows = query.order_by(SystemEvent.created_at.desc()).offset(page * page_size).limit(page_size).all()
        
        events = []
        for r in rows:
            events.append({
                "id": r.id,
                "event_type": r.event_type,
                "actor": r.actor,
                "session_id": r.session_id,
                "framework": r.framework,
                "meta": r.meta,
                "severity": r.severity,
                "created_at": str(r.created_at)
            })
        return {
            "success": True, 
            "events": events, 
            "page": page, 
            "page_size": page_size, 
            "total_count": total_count,
            "total_pages": (total_count + page_size - 1) // page_size
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch system events.")
    finally:
        db.close()

@router.get("/audit-trail")
def api_get_audit_trail(
    request: Request,
    page: int = Query(0, ge=0),
    page_size: int = Query(20, ge=1, le=100)
):
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    db = SessionLocal()
    try:
        query = db.query(AuditTrail)
        total_count = query.count()
        rows = query.order_by(AuditTrail.run_date.desc()).offset(page * page_size).limit(page_size).all()
        
        trail = []
        for r in rows:
            trail.append({
                "id": r.id,
                "audit_id": r.audit_id,
                "document_name": r.document_name,
                "standard": r.standard,
                "model_used": r.model_used,
                "run_date": str(r.run_date),
                "total_controls": r.total_controls
            })
        return {
            "success": True,
            "trail": trail,
            "page": page,
            "page_size": page_size,
            "total_count": total_count,
            "total_pages": (total_count + page_size - 1) // page_size
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch audit trail.")
    finally:
        db.close()

@router.get("/developer")
def api_get_developer_logs(request: Request):
    user = _require_auth(request)  # logs contain sensitive server info
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    if not os.path.exists(LOG_PATH):
        return {"success": True, "logs": "", "message": "No logs recorded yet."}
    
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            logs = f.read()
        return {"success": True, "logs": logs}
    except Exception as e:
        print(f"[LOG READ ERROR] {e}", flush=True)
        raise HTTPException(status_code=500, detail="Failed to read developer log file.")

@router.delete("/developer")
def api_clear_developer_logs(request: Request):
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    try:
        if os.path.exists(LOG_PATH):
            os.remove(LOG_PATH)
            return {"success": True, "message": "Developer log file successfully cleared."}
        return {"success": True, "message": "No log file existed to delete."}
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to delete log file.")

@router.post("/purge")
def api_purge_logs(request: Request, days: int = Query(90, ge=1)):
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    try:
        deleted = purge_old_logs(days=days)
        return {"success": True, "message": f"Successfully purged {deleted} events older than {days} days."}
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to purge logs.")


# ─────────────────────────────────────────────────────────────────────────────
# LIVE METRICS ENDPOINT — Powered by Redis Stream
# Powers the "Live Server Metrics (Redis Stream)" KPI panel + Active Sessions
# table in the Admin Dashboard. Falls back to zeros if Redis is offline.
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/live-metrics")
def api_get_live_metrics(request: Request, limit: int = 500):
    """
    Returns live token counts, latency, file sizes, error counts, and
    per-session active auditor metrics from Redis or ShaktiDB fallback.
    Accepts optional ?limit= query parameter (defaults to 500).
    """
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    try:
        from src.core.redis_metrics import get_live_metrics
        data = get_live_metrics(limit=limit)
        return {"success": True, **data}
    except Exception as e:
        return {
            "success": True,
            "redis_available": False,
            "global_tokens": 0,
            "global_latency_sec": 0.0,
            "global_latency_str": "0m 0.0s",
            "avg_latency_per_ctrl_str": "0m 0.0s",
            "global_files": 0,
            "global_errors": 0,
            "active_sessions": []
        }



# ─────────────────────────────────────────────────────────────────────────────
# EXPORT ENDPOINTS — System Event Logs & Telemetry Benchmark
# All support optional ?auditor_user= filter for per-user or combined reports.
# Works with PostgreSQL (ShaktiDB) and SQLite fallback — pure SQLAlchemy ORM.
# ─────────────────────────────────────────────────────────────────────────────
import tempfile, uuid as _uuid
from datetime import datetime as _dt
from fastapi.responses import FileResponse as _FileResponse


def _fetch_system_events(auditor_user: Optional[str] = None) -> list:
    """Fetch SystemEvent rows as dicts. Works for PostgreSQL and SQLite."""
    db = SessionLocal()
    try:
        q = db.query(SystemEvent)
        if auditor_user and auditor_user.strip() and auditor_user.lower() != "all":
            q = q.filter(SystemEvent.actor.ilike(f"%{auditor_user.strip()}%"))
        rows = q.order_by(SystemEvent.created_at.desc()).limit(5000).all()
        return [
            {
                "created_at": str(r.created_at) if r.created_at else "",
                "actor":      r.actor or "SYSTEM",
                "severity":   r.severity or "INFO",
                "event_type": r.event_type or "",
                "session_id": r.session_id or "",
                "framework":  r.framework or "",
                "meta":       r.meta or "",
            }
            for r in rows
        ]
    finally:
        db.close()


def _fetch_benchmark_records(auditor_user: Optional[str] = None) -> list:
    """
    Load telemetry records (real auditor username already joined in by
    get_all_benchmark_records() via AuditReport.created_by), optionally filtered
    to one auditor.

    Previously this filtered against session_id or folder_name -- neither field
    has ever contained a username (session_id is a random uuid4 hex, folder_name
    is a constant "Audit Evidence Package"), so the filter could never actually
    match a real auditor and every export was effectively unfiltered or empty.
    """
    try:
        from src.core.token_tracker import get_all_benchmark_records
        records = get_all_benchmark_records()
        if auditor_user and auditor_user.strip() and auditor_user.lower() != "all":
            au = auditor_user.strip().lower()
            records = [r for r in records if au in str(r.get("auditor_username", "")).lower()]
        return records
    except Exception:
        return []


@router.get("/system/export-excel")
def api_export_system_logs_excel(
    request: Request,
    auditor_user: Optional[str] = Query(None, description="Filter by auditor username")
):
    """
    Download System Audit Event Logs as a styled Excel (.xlsx) file.
    Supports optional ?auditor_user= filter. Works with PostgreSQL & SQLite.
    """
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    from src.core.token_tracker import generate_excel_system_logs_report
    logs = _fetch_system_events(auditor_user)
    ts   = _dt.utcnow().strftime("%Y%m%d_%H%M%S")
    slug = (auditor_user or "all").replace("@", "_").replace(".", "_")
    os.makedirs("data/tmp", exist_ok=True)
    out  = f"data/tmp/System_Event_Logs_{slug}_{ts}.xlsx"
    try:
        generate_excel_system_logs_report(logs, out)
    except Exception:
        raise HTTPException(status_code=500, detail="Export failed. Please try again.")
    return _FileResponse(
        path=out,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=os.path.basename(out),
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(out)}"'}
    )


@router.get("/system/export-pdf")
def api_export_system_logs_pdf(
    request: Request,
    auditor_user: Optional[str] = Query(None, description="Filter by auditor username")
):
    """
    Download System Audit Event Logs as an executive PDF (.pdf) file.
    Supports optional ?auditor_user= filter. Works with PostgreSQL & SQLite.
    """
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    from src.core.token_tracker import generate_pdf_system_logs_report
    logs = _fetch_system_events(auditor_user)
    ts   = _dt.utcnow().strftime("%Y%m%d_%H%M%S")
    slug = (auditor_user or "all").replace("@", "_").replace(".", "_")
    os.makedirs("data/tmp", exist_ok=True)
    out  = f"data/tmp/System_Event_Logs_{slug}_{ts}.pdf"
    try:
        generate_pdf_system_logs_report(logs, out)
    except Exception:
        raise HTTPException(status_code=500, detail="Export failed. Please try again.")
    return _FileResponse(
        path=out,
        media_type="application/pdf",
        filename=os.path.basename(out),
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(out)}"'}
    )


@router.get("/benchmark/export-excel")
def api_export_benchmark_excel(
    request: Request,
    auditor_user: Optional[str] = Query(None, description="Filter by auditor username")
):
    """
    Download Telemetry Benchmark Report as a styled Excel (.xlsx) file.
    Supports optional ?auditor_user= filter. Works with PostgreSQL & SQLite.
    """
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    from src.core.token_tracker import generate_excel_benchmark_report
    records = _fetch_benchmark_records(auditor_user)
    ts      = _dt.utcnow().strftime("%Y%m%d_%H%M%S")
    slug    = (auditor_user or "all").replace("@", "_").replace(".", "_")
    os.makedirs("data/tmp", exist_ok=True)
    out     = f"data/tmp/Executive_Telemetry_Report_{slug}_{ts}.xlsx"
    try:
        generate_excel_benchmark_report(records, out)
    except Exception:
        raise HTTPException(status_code=500, detail="Export failed. Please try again.")
    return _FileResponse(
        path=out,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=os.path.basename(out),
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(out)}"'}
    )


@router.get("/benchmark/export-pdf")
def api_export_benchmark_pdf(
    request: Request,
    auditor_user: Optional[str] = Query(None, description="Filter by auditor username")
):
    """
    Download Telemetry Benchmark Report as an executive PDF (.pdf) file.
    Supports optional ?auditor_user= filter. Works with PostgreSQL & SQLite.
    """
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    from src.core.token_tracker import generate_pdf_benchmark_report
    records = _fetch_benchmark_records(auditor_user)
    ts      = _dt.utcnow().strftime("%Y%m%d_%H%M%S")
    slug    = (auditor_user or "all").replace("@", "_").replace(".", "_")
    os.makedirs("data/tmp", exist_ok=True)
    out     = f"data/tmp/Executive_Telemetry_Report_{slug}_{ts}.pdf"
    try:
        generate_pdf_benchmark_report(records, out, auditor_filter=auditor_user)
    except Exception:
        raise HTTPException(status_code=500, detail="Export failed. Please try again.")
    return _FileResponse(
        path=out,
        media_type="application/pdf",
        filename=os.path.basename(out),
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(out)}"'}
    )
