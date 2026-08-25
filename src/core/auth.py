# -*- coding: utf-8 -*-
"""
Core Authentication Module
Pure Python module for user authentication, password hashing, and user registration.
Decoupled from Streamlit UI.
"""

import hashlib
import re
import os
import secrets
import string
import bcrypt
import pyotp
from src.db.database import SessionLocal, User, force_master


def _generate_iso_compliant_password(length: int = 20) -> str:
    """Cryptographically random password guaranteed to pass validate_iso_password()
    (at least one upper/lower/digit/special char), not just probably does."""
    upper, lower, digit = string.ascii_uppercase, string.ascii_lowercase, string.digits
    special = "!@#$%^&*()_+-="
    required = [secrets.choice(upper), secrets.choice(lower), secrets.choice(digit), secrets.choice(special)]
    pool = upper + lower + digit + special
    rest = [secrets.choice(pool) for _ in range(max(0, length - len(required)))]
    chars = required + rest
    _rand = secrets.SystemRandom()
    _rand.shuffle(chars)
    return "".join(chars)


def _hash_pw(pw: str) -> str:
    """Returns a salted bcrypt hash of a plain text password."""
    return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def _hash_pw_sha256_legacy(pw: str) -> str:
    """Legacy unsalted SHA256 hash -- kept only to verify passwords hashed
    before the bcrypt migration. Never used to hash new passwords."""
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()


def _verify_pw(pw: str, stored_hash: str) -> bool:
    """Verifies a password against either a bcrypt hash or a legacy SHA256
    hash. Bcrypt hashes always start with "$2"; anything else is treated as
    a legacy SHA256 hex digest."""
    if not stored_hash:
        return False
    if stored_hash.startswith("$2"):
        try:
            return bcrypt.checkpw(pw.encode('utf-8'), stored_hash.encode('utf-8'))
        except ValueError:
            return False
    return secrets.compare_digest(_hash_pw_sha256_legacy(pw), stored_hash)

def validate_username(username: str) -> tuple[bool, str]:
    """
    Enforces Universal Email Address rule:
    Usernames must be a valid email address with any valid domain extension (e.g. user@gmail.com, user@company.com, user@college.ac.in).
    Admin ('admin') and system test accounts are explicitly exempt.
    """
    uname = (username or "").strip().lower()
    if uname in ("admin", "auditor@24", "auditee2@organization.com"):
        return True, ""
    
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, uname, re.IGNORECASE):
        return False, "Username must be a valid email address (e.g., user@gmail.com, user@company.com, or user@college.ac.in)."
    return True, ""

def validate_iso_password(password: str) -> tuple[bool, str]:
    """
    Enforces ISO 27001 / ISO 27002 A.5.17 password security policy:
    - Minimum 8 characters long
    - At least 1 uppercase letter (A-Z)
    - At least 1 lowercase letter (a-z)
    - At least 1 number (0-9)
    - At least 1 special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
    """
    pw = password or ""
    if len(pw) < 8:
        return False, "Password must be at least 8 characters long under ISO 27001 policy."
    if not re.search(r"[A-Z]", pw):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", pw):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", pw):
        return False, "Password must contain at least one digit (0-9)."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", pw):
        return False, "Password must contain at least one special character (e.g. @, #, $, !)."
    return True, ""

def seed_default_admin():
    """
    Ensures a default admin user exists in database.

    Never falls back to a hardcoded password -- that string was a real,
    exploitable credential once it sat in source control. Uses
    ADMIN_DEFAULT_PASSWORD if explicitly set; otherwise generates a real
    random one that passes the ISO password policy and prints it once so
    whoever is standing up this instance can actually log in.
    """
    with force_master():
        db = SessionLocal()
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            password = os.environ.get("ADMIN_DEFAULT_PASSWORD", "").strip()
            if not password:
                password = _generate_iso_compliant_password()
                print(
                    "=" * 70 + "\n"
                    "[AUTH] ADMIN_DEFAULT_PASSWORD not set -- generated a random admin "
                    f"password:\n\n    {password}\n\n"
                    "SAVE THIS NOW, it will not be shown again. Set ADMIN_DEFAULT_PASSWORD "
                    "explicitly for future deployments.\n" + "=" * 70,
                    flush=True
                )
            totp_secret = os.environ.get("ADMIN_TOTP_SECRET", "").strip() or pyotp.random_base32()
            db.add(User(
                username="admin",
                password_hash=_hash_pw(password),
                role="admin",
                totp_secret=totp_secret
            ))
            db.commit()
        elif not admin.totp_secret:
            admin.totp_secret = os.environ.get("ADMIN_TOTP_SECRET", "").strip() or pyotp.random_base32()
            db.commit()
        db.close()

def authenticate_user(username: str, password: str):
    """Authenticates user credentials and returns user details if valid.

    Transparently upgrades a legacy SHA256 password hash to bcrypt on
    successful login, so hashes get stronger over time without requiring
    a mass password reset."""
    with force_master():
        db = SessionLocal()
        user = db.query(User).filter(User.username == username).first()
        if not user or not _verify_pw(password, user.password_hash):
            db.close()
            return None

        if not user.password_hash.startswith("$2"):
            user.password_hash = _hash_pw(password)
            db.commit()

        result = {
            "username": user.username,
            "role": user.role,
            "totp_secret": user.totp_secret
        }
        db.close()
        return result

def register_user(username: str, password: str, role: str):
    """Registers a new user in database with Gmail username and ISO 27001 password verification."""
    # 1. Username Gmail validation
    u_ok, u_msg = validate_username(username)
    if not u_ok:
        return False, u_msg, None

    # 2. ISO 27001 password policy validation
    p_ok, p_msg = validate_iso_password(password)
    if not p_ok:
        return False, p_msg, None

    with force_master():
        db = SessionLocal()
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            db.close()
            return False, "Username already exists.", None
        secret = pyotp.random_base32()
        db.add(User(
            username=username,
            password_hash=_hash_pw(password),
            role=role,
            totp_secret=secret
        ))
        db.commit()
        db.close()
        return True, "Account created successfully!", secret
