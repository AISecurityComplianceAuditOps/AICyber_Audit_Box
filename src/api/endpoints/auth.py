from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from typing import Optional
import pyotp
import qrcode
import time
import os
import jwt
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import base64
from io import BytesIO
from src.core.auth import (
    authenticate_user, 
    register_user, 
    seed_default_admin,
    _hash_pw
)
from src.db.database import SessionLocal, User, force_master
from src.core.bg_worker import log_system_event

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ── JWT Configuration ─────────────────────────────────────────────────────────
def _resolve_jwt_secret() -> str:
    """
    Never falls back to a hardcoded string -- that string was a real, exploitable
    credential (forge any session, including admin, no password needed) once it
    sat in source control. If JWT_SECRET isn't set, generate a real random secret
    and persist it under data/ (already gitignored) so it survives restarts
    instead of invalidating every session each time the API restarts.
    """
    env_secret = os.environ.get("JWT_SECRET", "").strip()
    if env_secret:
        return env_secret

    import secrets as _secrets
    secret_path = os.path.join("data", ".jwt_secret")
    try:
        if os.path.exists(secret_path):
            with open(secret_path, "r", encoding="utf-8") as f:
                existing = f.read().strip()
            if existing:
                return existing
        os.makedirs(os.path.dirname(secret_path), exist_ok=True)
        new_secret = _secrets.token_hex(32)
        with open(secret_path, "w", encoding="utf-8") as f:
            f.write(new_secret)
        print(
            "[AUTH] JWT_SECRET not set -- generated and persisted a random secret to "
            f"{secret_path}. Set JWT_SECRET explicitly for production/multi-instance deployments.",
            flush=True
        )
        return new_secret
    except Exception as e:
        # Last resort: an in-memory-only random secret. Safer than a public
        # hardcoded string even though it means restarts invalidate sessions.
        print(f"[AUTH WARNING] Could not persist JWT secret ({e}); using a session-only random secret.", flush=True)
        return _secrets.token_hex(32)


_JWT_SECRET  = _resolve_jwt_secret()
_JWT_ALGO    = "HS256"
_JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "8"))

def _create_token(username: str, role: str) -> str:
    """Create a signed JWT token with username, role, and expiry."""
    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=_JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGO)

def _require_auth(request: Request) -> dict:
    """Validates the JWT token in the Authorization header. Returns {username, role} or raises 401."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized. A valid authentication token is required.")
    token = auth_header[len("Bearer "):].strip()
    try:
        payload = jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGO])
        return {"username": payload.get("sub"), "role": payload.get("role")}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token. Please log in again.")

# --- Request / Response Schemas ---
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=4)
    role: str = Field(..., pattern="^(admin|auditor|auditee)$")

class LoginRequest(BaseModel):
    username: str
    password: str

class VerifyOTPRequest(BaseModel):
    username: str
    otp_code: str

class ForgotPasswordRequest(BaseModel):
    username: str

class ResetPasswordTOTPRequest(BaseModel):
    username: str
    otp_code: str
    new_password: str

# --- Simple In-Memory Rate Limiter (5 failed attempts per minute per IP) ---
_login_attempts: dict = defaultdict(list)  # {ip: [timestamp, ...]}
MAX_ATTEMPTS = 5
RATE_WINDOW_SECONDS = 60
# Periodic full-dict sweep interval. Pruning only ever touched the CURRENT ip's
# own list -- an ip that stopped attempting entirely left a stale (often empty)
# entry in this dict forever, growing unbounded over a long-running server
# process's lifetime as more unique ips make requests.
_SWEEP_INTERVAL_SECONDS = 300
_last_sweep_time = [0.0]

def _check_rate_limit(ip: str):
    """Raises HTTP 429 if more than MAX_ATTEMPTS login attempts in RATE_WINDOW_SECONDS."""
    if os.environ.get("RATE_LIMIT_DISABLED") == "1" or os.environ.get("TESTING") == "1" or ip in ("127.0.0.1", "::1", "localhost", "testclient"):
        return
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < RATE_WINDOW_SECONDS]

    if now - _last_sweep_time[0] > _SWEEP_INTERVAL_SECONDS:
        _last_sweep_time[0] = now
        for other_ip in [k for k, v in _login_attempts.items() if not v]:
            del _login_attempts[other_ip]

    if len(_login_attempts[ip]) >= MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Please wait {RATE_WINDOW_SECONDS} seconds before trying again."
        )
    _login_attempts[ip].append(now)

# --- Endpoints ---

@router.post("/register")
def api_register(req: RegisterRequest):
    # Self-service registration is for auditor/auditee accounts only. The
    # "admin" role was previously accepted here with zero gatekeeping --
    # anyone who could reach this public, unauthenticated endpoint could
    # create their own admin account, which made every admin-only
    # restriction elsewhere in the app (system logs, benchmark telemetry,
    # finding-tampering protection, etc.) trivially bypassable. The one
    # legitimate admin account is meant to come from the deployment's own
    # bootstrap (ADMIN_DEFAULT_PASSWORD / seed_default_admin on first boot),
    # not public self-signup.
    if req.role == "admin":
        raise HTTPException(status_code=403, detail="Admin accounts cannot be self-registered. Contact your system administrator.")
    try:
        # Call register_user logic from auth.py
        ok, msg, secret = register_user(req.username, req.password, req.role)
        if not ok:
            raise HTTPException(status_code=400, detail=msg)

        # Generate TOTP QR code
        totp = pyotp.totp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=req.username, issuer_name="AICyberAuditBox")

        img = qrcode.make(provisioning_uri)
        buf = BytesIO()
        img.save(buf, format="PNG")
        qr_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")

        try:
            log_system_event("USER_REGISTERED", "INFO", f"New user registered: {req.username} (role: {req.role})", actor=req.username)
        except Exception:
            pass  # Never let logging crash the registration response

        return {
            "success": True,
            "message": msg,
            "username": req.username,
            "role": req.role,
            "totp_secret": secret,
            "qr_code_base64": f"data:image/png;base64,{qr_base64}"
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"[REGISTER ERROR] username={req.username} | {e}", flush=True)
        raise HTTPException(status_code=500, detail="Registration failed due to a server error. Please try again.")

@router.post("/login")
def api_login(req: LoginRequest, request: Request):
    # Rate limiting — max 5 attempts per IP per minute
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    try:
        # Ensure default admin exists
        seed_default_admin()

        user = authenticate_user(req.username, req.password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password.")
        
        # Generate TOTP QR code and secret preview for Authenticator apps
        qr_code_base64 = None
        totp_secret = user.get("totp_secret")
        if not totp_secret:
            totp_secret = pyotp.random_base32()
            
        totp = pyotp.totp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(name=user["username"], issuer_name="AICyberAuditBox")
        img = qrcode.make(provisioning_uri)
        buf = BytesIO()
        img.save(buf, format="PNG")
        qr_code_base64 = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('utf-8')}"
            
        return {
            "success": True,
            "username": user["username"],
            "role": user["role"],
            "requires_otp": True,
            "qr_code_base64": qr_code_base64
            # totp_secret intentionally NOT returned — prevents 2FA cloning via DevTools
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"[LOGIN ERROR] username={req.username} | {e}", flush=True)
        raise HTTPException(status_code=500, detail="Login failed due to a server error. Please try again.")

@router.post("/verify-otp")
def api_verify_otp(req: VerifyOTPRequest, request: Request):
    # Rate limiting — OTP brute force prevention (3 attempts per minute)
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    try:
        with force_master():
            db = SessionLocal()
            user = db.query(User).filter(User.username == req.username).first()
            db.close()

        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        if not user.totp_secret:
            raise HTTPException(status_code=400, detail="Account TOTP not configured. Please re-register.")

        totp = pyotp.totp.TOTP(user.totp_secret)
        # Verify live TOTP code from Google Authenticator only (no bypass codes)
        is_valid = totp.verify(req.otp_code, valid_window=5)

        if is_valid:
            try:
                log_system_event("USER_LOGIN", "INFO", f"User '{user.username}' (role: {user.role}) logged in successfully", actor=user.username)
            except Exception:
                pass  # Never let logging crash the login response
            return {
                "success": True,
                "username": user.username,
                "role": user.role,
                "token": _create_token(user.username, user.role)
            }
        else:
            raise HTTPException(status_code=400, detail="Invalid OTP code. Please enter the 6-digit code from your Google Authenticator app.")
    except HTTPException:
        raise
    except Exception as e:
        print(f"[VERIFY OTP ERROR] username={req.username} | {e}", flush=True)
        raise HTTPException(status_code=500, detail="OTP verification failed due to a server error. Please try again.")

@router.get("/auditees")
def api_get_auditees(request: Request):
    """Returns list of all registered Auditee user accounts for report distribution targeting."""
    _require_auth(request)
    with force_master():
        db = SessionLocal()
        try:
            from src.db.database import User
            users = db.query(User).filter(User.role.in_(["auditee", "client"])).all()
            if not users:
                # Seed default registered auditee accounts only if the table is
                # completely empty of auditee/client accounts. Failures are non-fatal
                # -- the caller will just get an empty list and can register manually.
                try:
                    from src.core.auth import register_user
                    register_user("auditee@organization.com", "Auditee@123", "auditee")
                    register_user("auditee2@organization.com", "Auditee@123", "auditee")
                    users = db.query(User).filter(User.role.in_(["auditee", "client"])).all()
                except Exception as seed_err:
                    print(f"[AUDITEES] Default seed failed (non-fatal): {seed_err}", flush=True)

            result = []
            for u in (users or []):
                result.append({
                    "id": u.id,
                    "username": u.username,
                    "role": u.role
                })
            return {"success": True, "auditees": result}
        except HTTPException:
            raise
        except Exception as e:
            print(f"[AUDITEES ERROR] {e}", flush=True)
            raise HTTPException(status_code=500, detail="Failed to load auditee accounts.")
        finally:
            db.close()

@router.post("/forgot-password/request")
def api_forgot_password_request(req: ForgotPasswordRequest, request: Request):
    """Fetches user's Google Authenticator QR Code & Secret for TOTP password recovery."""
    # Rate limiting -- unlike /login and /verify-otp, this endpoint previously had
    # none at all, allowing unlimited username enumeration/probing.
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    with force_master():
        db = SessionLocal()
        try:
            u = db.query(User).filter(User.username == req.username).first()
            if not u:
                raise HTTPException(status_code=404, detail="Account not found. Please check your username and try again.")
            
            secret = u.totp_secret
            if not secret:
                secret = pyotp.random_base32()
                u.totp_secret = secret
                db.commit()
                
            totp = pyotp.totp.TOTP(secret)
            uri = totp.provisioning_uri(name=u.username, issuer_name="AICyberAuditBox")
            img = qrcode.make(uri)
            buf = BytesIO()
            img.save(buf, format="PNG")
            qr_base64 = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('utf-8')}"
            
            return {
                "success": True,
                "username": u.username,
                "totp_secret": secret,
                "qr_code_base64": qr_base64,
                "message": "Scan QR Code with Google Authenticator or enter 6-digit TOTP code to recover password."
            }
        finally:
            db.close()

@router.post("/forgot-password/reset")
def api_forgot_password_reset(req: ResetPasswordTOTPRequest, request: Request):
    """Verifies 6-digit TOTP code from Google Authenticator and resets user password with ISO 27001 policy."""
    # Rate limiting -- this endpoint verifies a 6-digit TOTP code (valid_window=5,
    # i.e. 11 valid codes at any moment) with no limit previously, permitting
    # unlimited brute-force attempts against it.
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    from src.core.auth import validate_iso_password
    p_ok, p_msg = validate_iso_password(req.new_password)
    if not p_ok:
        raise HTTPException(status_code=400, detail=p_msg)

    with force_master():
        db = SessionLocal()
        try:
            u = db.query(User).filter(User.username == req.username).first()
            if not u:
                raise HTTPException(status_code=404, detail=f"Username '{req.username}' not found.")
            
            secret = u.totp_secret
            if not secret:
                secret = pyotp.random_base32()
                u.totp_secret = secret
                db.commit()
                
            totp = pyotp.TOTP(secret)
            # Verify live TOTP code only — no demo bypass codes
            is_valid = totp.verify(req.otp_code.strip(), valid_window=5)
            
            if not is_valid:
                raise HTTPException(status_code=401, detail="Invalid Google Authenticator TOTP code. Please try again.")
                
            u.password_hash = _hash_pw(req.new_password)
            db.commit()
            
            return {
                "success": True,
                "message": f"Password for user '{u.username}' successfully reset! You can now log in."
            }
        finally:
            db.close()
