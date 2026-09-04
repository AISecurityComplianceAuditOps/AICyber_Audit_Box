import sys
import asyncio
import os
import warnings

# Windows' default console codepage (cp1252) can't encode emoji used in several
# log/print statements (e.g. audit.py's "started" message) -- that raised an
# unhandled UnicodeEncodeError and crashed the request entirely (500 Internal
# Server Error with no JSON body) any time a print() with an emoji ran inside
# a request handler on a plain Windows terminal. Reconfiguring stdout/stderr
# to UTF-8 here, before anything else prints, fixes it at the source instead
# of chasing every individual print statement.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Silence third-party library deprecation/version noise (LangChain / Pydantic V1)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", message=".*Pydantic.*")

if sys.platform == "win32":
    # Silence harmless Windows Proactor connection lost exception noise on socket reset
    try:
        from asyncio.proactor_events import _ProactorBasePipeTransport
        _old_call_connection_lost = _ProactorBasePipeTransport._call_connection_lost

        def _silent_call_connection_lost(self, exc=None):
            try:
                _old_call_connection_lost(self, exc)
            except (ConnectionResetError, OSError):
                pass

        _ProactorBasePipeTransport._call_connection_lost = _silent_call_connection_lost
    except Exception:
        pass

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn


from src.api.endpoints.auth import router as auth_router
from src.api.endpoints.controls import router as controls_router
from src.api.endpoints.logs import router as logs_router
from src.api.endpoints.audit import router as audit_router
from src.api.endpoints.license import router as license_router

# Sentry error tracking — no-op until SENTRY_DSN is set (see qa/monitoring/README.md)
_sentry_dsn = os.environ.get("SENTRY_DSN")
if _sentry_dsn:
    import sentry_sdk
    sentry_sdk.init(dsn=_sentry_dsn, traces_sample_rate=0.1, send_default_pii=False)

app = FastAPI(
    title="AICyberAuditBox - Local API Server",
    description="Offline REST API Server for RAG ISO 27001 Compliance Audit Intelligence",
    version="1.0.0",
    docs_url=None,      # Disable /docs in production (security: hides API schema from attackers)
    redoc_url=None,     # Disable /redoc in production
    openapi_url=None,   # Disable /openapi.json in production
)

from starlette.middleware.base import BaseHTTPMiddleware

class NoCacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/static") or request.url.path == "/":
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        # --- Security Headers (prevent pentest findings) ---
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self';"
        )
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

app.add_middleware(NoCacheMiddleware)

# CORS: restrict to localhost/127.0.0.1 only (no wildcard -- "*" + allow_credentials=True
# is an invalid CORS combination that browsers reject with a network error)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "https://localhost",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://localhost:443",
        "https://127.0.0.1:443",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

from fastapi.responses import FileResponse, RedirectResponse



# Register endpoints routers
app.include_router(auth_router, prefix="/api")
app.include_router(controls_router, prefix="/api")
app.include_router(logs_router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(license_router)

# Mount static files folder
app.mount("/static", StaticFiles(directory="src/api/static"), name="static")

@app.get("/")
def read_root():
    headers = {
        "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0"
    }
    return FileResponse("src/api/static/index.html", headers=headers)

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    from fastapi.responses import Response
    return Response(status_code=204)

if __name__ == "__main__":
    port = int(os.environ.get("API_PORT", 8000))
    print(f"Starting AICyberAuditBox Local API server on 127.0.0.1:{port}...", flush=True)
    uvicorn.run("src.api.main:app", host="127.0.0.1", port=port, reload=True)
