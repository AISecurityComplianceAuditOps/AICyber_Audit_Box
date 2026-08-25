# -*- coding: utf-8 -*-
"""
License & Token Billing Endpoint Router
Implements Time-Bound & Audit-Count Limited Free Trial & Token-to-Rupee Billing.
"""

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, field_validator
from typing import Optional, List
from src.db.database import SessionLocal, LicenseWallet, TokenUsageLog, force_master
from src.api.endpoints.auth import _require_auth
from src.core.text_validation import clean_safe_text as _clean_safe_text

router = APIRouter(prefix="/api/license", tags=["License & Token Billing"])

class LicenseActivateRequest(BaseModel):
    license_key: str

    @field_validator("license_key")
    @classmethod
    def _validate_license_key(cls, v):
        return _clean_safe_text(v, "License Key", 100, required=True)

class TokenDeductRequest(BaseModel):
    session_id: str
    control_id: Optional[str] = None
    prompt_tokens: int
    completion_tokens: int

def _get_or_create_default_wallet(db):
    """Retrieves active wallet or creates default 14-day 5-audit free trial wallet."""
    with force_master():
        wallet = db.query(LicenseWallet).filter(LicenseWallet.is_active == True).first()
        if not wallet:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            expiry = now + timedelta(days=14)
            wallet = LicenseWallet(
                license_key="STPI-FREE-TRIAL-2026",
                license_type="TRIAL",
                auditor_group="STPI / VAPT Free Trial Auditor",
                balance_rupees=500.0,          # ₹500 starter credit
                rate_per_m_tokens=10.0,        # ₹10 per 1M tokens
                allocated_tokens=50000000,
                used_tokens=0,
                audits_allowed=5,              # 5 Full Audits allowed in Trial
                audits_completed=0,
                expiry_days=14,
                created_at=now,
                expiry_date=expiry,
                is_active=True
            )
            db.add(wallet)
            db.commit()
            db.refresh(wallet)
        return wallet

@router.get("/wallet")
def get_license_wallet_status(request: Request):
    """Returns the real active license wallet status from the database."""
    _require_auth(request)
    db = SessionLocal()
    try:
        with force_master():
            wallet = _get_or_create_default_wallet(db)
            now = datetime.now(timezone.utc).replace(tzinfo=None)

            days_remaining = 0
            is_expired = True
            if wallet.expiry_date:
                delta = wallet.expiry_date - now
                days_remaining = max(0, delta.days)
                is_expired = delta.total_seconds() <= 0

            return {
                "status": "EXPIRED" if is_expired else "ACTIVE",
                "license_key": wallet.license_key,
                "license_type": wallet.license_type,
                "auditor_group": wallet.auditor_group,
                "balance_rupees": round(wallet.balance_rupees, 2),
                "rate_per_m_tokens": wallet.rate_per_m_tokens,
                "allocated_tokens": wallet.allocated_tokens,
                "used_tokens": wallet.used_tokens,
                "audits_allowed": wallet.audits_allowed,
                "audits_completed": wallet.audits_completed,
                "audits_remaining": max(0, wallet.audits_allowed - wallet.audits_completed),
                "days_remaining": days_remaining,
                "expiry_date": wallet.expiry_date.isoformat() if wallet.expiry_date else None,
                "is_expired": is_expired,
                "message": "License Expired. Please renew." if is_expired else "License Active"
            }
    finally:
        db.close()


@router.post("/activate")
def activate_license(request: Request, req: LicenseActivateRequest):
    """Activates an enterprise key or recharges trial credit balance. Admin only."""
    user = _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admin only.")
    db = SessionLocal()
    try:
        key_clean = req.license_key.strip().upper()
        if not key_clean:
            raise HTTPException(status_code=400, detail="License key cannot be empty.")
            
        with force_master():
            wallet = _get_or_create_default_wallet(db)
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            
            # Parse parameters from key format e.g. STPI-30D-20A-2000INR-SIG
            import re
            match = re.match(r'^([A-Z0-9]+)-(\d+)D-(\d+)A-(\d+)INR-([A-Z0-9]+)$', key_clean)
            if match:
                prefix, days, audits, credit, sig = match.groups()
                days_add = int(days)
                audits_add = int(audits)
                credit_add = float(credit)
                
                wallet.license_type = "ENTERPRISE" if "ENT" in prefix or "PRO" in prefix else "STPI_TRIAL"
                wallet.license_key = key_clean
                wallet.balance_rupees += credit_add
                wallet.audits_allowed += audits_add
                wallet.audits_completed = 0  # reset completed count on fresh key
                wallet.expiry_date = (wallet.expiry_date if wallet.expiry_date and wallet.expiry_date > now else now) + timedelta(days=days_add)
                wallet.is_active = True
                db.commit()
                return {
                    "message": f"License Activated! Added +{days_add} Days, +{audits_add} Audits, and +₹{credit_add:.2f} Credit Balance.",
                    "new_balance": wallet.balance_rupees
                }

            if "ENTERPRISE" in key_clean or "PRO" in key_clean or "STPI" in key_clean:
                wallet.license_type = "ENTERPRISE"
                wallet.license_key = key_clean
                wallet.balance_rupees += 5000.0  # Add ₹5,000 credit
                wallet.audits_allowed += 100     # Add 100 audits
                wallet.expiry_date = now + timedelta(days=365) # 1 Year extension
                wallet.is_active = True
                db.commit()
                return {"message": "Enterprise License Activated Successfully!", "new_balance": wallet.balance_rupees}
            else:
                wallet.balance_rupees += 500.0
                wallet.audits_allowed += 5
                wallet.expiry_date = now + timedelta(days=30)
                db.commit()
                return {"message": "License Key Top-up Applied Successfully!", "new_balance": wallet.balance_rupees}
    finally:
        db.close()

@router.post("/deduct")
def deduct_tokens(request: Request, req: TokenDeductRequest):
    """Deducts tokens from active wallet balance and logs token transaction."""
    _require_auth(request)
    db = SessionLocal()
    try:
        with force_master():
            wallet = _get_or_create_default_wallet(db)
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            
            if wallet.expiry_date and (wallet.expiry_date - now).total_seconds() <= 0:
                raise HTTPException(status_code=403, detail="Free Trial Expired. Please renew license.")
                
            total_tok = req.prompt_tokens + req.completion_tokens
            cost = (total_tok / 1000000.0) * wallet.rate_per_m_tokens
            
            wallet.used_tokens += total_tok
            wallet.balance_rupees = max(0.0, wallet.balance_rupees - cost)
            
            log = TokenUsageLog(
                session_id=req.session_id,
                control_id=req.control_id,
                prompt_tokens=req.prompt_tokens,
                completion_tokens=req.completion_tokens,
                total_tokens=total_tok,
                cost_rupees=cost
            )
            db.add(log)
            db.commit()
            
            return {
                "deducted_tokens": total_tok,
                "cost_rupees": round(cost, 4),
                "remaining_balance": round(wallet.balance_rupees, 2)
            }
    finally:
        db.close()
