# -*- coding: utf-8 -*-
"""
Admin-editable runtime settings. Backed by the system_settings DB table so an
admin can change these from the UI (no code edit, no restart); falls back to
the hardcoded default for any key that hasn't been set yet.

Only covers the 5 upload-limit settings by design -- other limits discussed
(concurrency caps, LLM_SLOTS) either need a process restart (LLM_SLOTS is a
llama-server startup parameter) or were intentionally left as fixed code
constants.
"""
import time
import threading

# key -> (default_value, min, max) -- bounds enforced on every write so an
# admin can't accidentally set something nonsensical (e.g. a negative size,
# or a limit so high it reintroduces the DoS risk these caps exist to prevent).
UPLOAD_SETTINGS = {
    "max_file_size_mb":       (100, 1, 1000),
    "max_upload_total_mb":    (100, 1, 1000),
    "max_files_per_upload":   (30, 1, 200),
    "max_zip_uncompressed_mb": (500, 10, 5000),
    "max_zip_ratio":          (100, 5, 1000),
}

_cache = {}
_cache_ts = {}
_cache_lock = threading.Lock()
_CACHE_TTL_SECONDS = 30


def get_setting(key: str) -> int:
    """Returns the current effective value for a known upload setting (int),
    checking a short-lived cache before the database so a hot path like file
    upload isn't hitting the DB on every single request."""
    if key not in UPLOAD_SETTINGS:
        raise KeyError(f"Unknown setting key: {key}")

    with _cache_lock:
        cached = _cache.get(key)
        ts = _cache_ts.get(key, 0)
        if cached is not None and (time.time() - ts) < _CACHE_TTL_SECONDS:
            return cached

    default_val, _min, _max = UPLOAD_SETTINGS[key]
    value = default_val
    try:
        from src.db.database import SessionLocal, SystemSetting, force_master
        with force_master():
            db = SessionLocal()
            try:
                row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
                if row is not None:
                    value = int(row.value)
            finally:
                db.close()
    except Exception as e:
        print(f"[SETTINGS] Failed to read '{key}' from DB, using default {default_val}: {e}", flush=True)
        value = default_val

    with _cache_lock:
        _cache[key] = value
        _cache_ts[key] = time.time()
    return value


def get_all_upload_settings() -> dict:
    return {key: get_setting(key) for key in UPLOAD_SETTINGS}


def set_setting(key: str, value: int, updated_by: str = None) -> int:
    """Validates against the key's bounds, persists, and invalidates the cache
    so the next read picks up the new value immediately (within this process)."""
    if key not in UPLOAD_SETTINGS:
        raise KeyError(f"Unknown setting key: {key}")
    _default, min_val, max_val = UPLOAD_SETTINGS[key]
    value = int(value)
    if value < min_val or value > max_val:
        raise ValueError(f"'{key}' must be between {min_val} and {max_val} (got {value}).")

    from src.db.database import SessionLocal, SystemSetting, force_master
    with force_master():
        db = SessionLocal()
        try:
            row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
            if row:
                row.value = str(value)
                row.updated_by = updated_by
            else:
                db.add(SystemSetting(key=key, value=str(value), updated_by=updated_by))
            db.commit()
        finally:
            db.close()

    with _cache_lock:
        _cache[key] = value
        _cache_ts[key] = time.time()
    return value
