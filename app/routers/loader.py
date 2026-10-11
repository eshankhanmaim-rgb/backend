import json
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import structlog
from fastapi import APIRouter, Request, Header, HTTPException, Query, Response

from app.core.config import get_settings
from app.core.errors import AppError, InvalidSession, InvalidCredentials, Forbidden
from app.core.security import (
    verify_password,
    generate_loader_session_token,
    hash_loader_session_token,
)
from app.core.crypto import (
    generate_x25519_keypair,
    derive_session_key,
    sign_response,
    generate_resource_key,
)
from app.core.rate_limit import check_lockout, record_failed_attempt, clear_failed_attempts
from app.core.audit import write_audit
from pydantic import BaseModel, Field

router = APIRouter(prefix="/loader", tags=["loader"])
log = structlog.get_logger()

class HWIDPayload(BaseModel):
    combined_hash: str
    components: List[str]

class LoaderLoginRequest(BaseModel):
    app_id: str
    build: str
    product_id: Optional[str] = None
    identifier: str
    password: str
    hwid: HWIDPayload
    client_nonce: str
    client_ephemeral_pub: str
    ts: int

class LoaderHeartbeatRequest(BaseModel):
    session_token: str
    seq: int
    nonce: str
    ts: int
    mac: str

class LoaderLogoutRequest(BaseModel):
    session_token: str

def compute_days_left(subscription: Dict[str, Any]) -> int:
    status = subscription.get("status", "none")
    if status == "lifetime" or subscription.get("lifetime"):
        return 9999
    if status != "active":
        return 0
    expires_at = subscription.get("expires_at")
    if not expires_at:
        return 0
    now = datetime.now(timezone.utc)
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
        except Exception:
            return 0
    elif hasattr(expires_at, "timestamp"):
        expires_at = datetime.fromtimestamp(expires_at.timestamp(), tz=timezone.utc)
    elif isinstance(expires_at, datetime) and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    delta = expires_at - now
    days = delta.days
    return max(0, days)

@router.get("/status")
async def loader_status(request: Request, app_id: Optional[str] = Query(None)):
    s = get_settings()
    req_app_id = request.headers.get("X-App-Id") or app_id
    if req_app_id != s.loader_app_id:
        raise AppError("UPDATE_REQUIRED", "Invalid application ID.", 403)
        
    db = request.state.db
    app_settings = await db.get_settings()
    resp_data = {
        "ok": True,
        "version": app_settings.get("current_loader_version", "1.0.0"),
        "min_version": app_settings.get("min_loader_version", "1.0.0"),
        "maintenance": app_settings.get("maintenance_mode", False)
    }
    raw_bytes = json.dumps(resp_data, separators=(',', ':'), default=str).encode('utf-8')
    sig = sign_response(raw_bytes)
    return Response(content=raw_bytes, media_type="application/json", headers={"X-Signature": sig})

@router.post("/login")
async def loader_login(body: LoaderLoginRequest, request: Request):
    s = get_settings()
    db = request.state.db
    now = datetime.now(timezone.utc)
    app_settings = await db.get_settings()
    
    if body.app_id != s.loader_app_id:
        raise AppError("UPDATE_REQUIRED", "Invalid application ID.", 403)
        
    if app_settings.get("maintenance_mode", False):
        raise AppError("MAINTENANCE_MODE", "Server is in maintenance mode.", 503)
        
    def parse_semver(v: str):
        try:
            return tuple(map(int, v.split('.')))
        except Exception:
            return (0, 0, 0)
    
    min_ver = app_settings.get("min_loader_version", s.loader_min_version)
    if parse_semver(body.build) < parse_semver(min_ver):
        raise AppError("UPDATE_REQUIRED", "Update required.", 403)
        
    # Timestamp anti-replay check
    if abs(int(now.timestamp()) - body.ts) > 180:
        raise AppError("TIME_DRIFT", "System time out of sync or packet replay.", 400)
        
    # Nonce check
    is_unique = await db.check_and_store_nonce(body.client_nonce, ttl_seconds=300)
    if not is_unique:
        raise AppError("REPLAY_ATTACK", "Nonce reused.", 400)
        
    client_ip = request.client.host if request.client else "127.0.0.1"
    await check_lockout(client_ip)
    await check_lockout(body.identifier)
    
    user = await db.get_user_by_identifier(body.identifier)
    if not user or not verify_password(body.password, user["password_hash"]):
        await record_failed_attempt(client_ip)
        await record_failed_attempt(body.identifier)
        await write_audit(action="loader.login_failed", actor="system", target=body.identifier, ip=client_ip, meta={"identifier": body.identifier})
        raise InvalidCredentials()
        
    await clear_failed_attempts(client_ip)
    await clear_failed_attempts(body.identifier)
        
    if user.get("banned", False):
        reason = user.get("ban_reason", "No reason provided")
        raise AppError("USER_BANNED", reason, 403)
        
    if not user.get("email_verified", False) and s.smtp_host:
        raise AppError("EMAIL_NOT_VERIFIED", "Email not verified.", 403)
        
    # HWID Verification
    user_hwid = user.get("hwid", {})
    if not user_hwid.get("combined_hash"):
        new_hwid = {
            "combined_hash": body.hwid.combined_hash,
            "components": body.hwid.components,
            "bound_at": now,
            "last_reset_at": user_hwid.get("last_reset_at")
        }
        await db.update_user(user["uid"], {"hwid": new_hwid})
        await write_audit("hwid.bound", user["uid"], {"hwid": body.hwid.combined_hash})
    else:
        if body.hwid.combined_hash != user_hwid.get("combined_hash"):
            db_components = user_hwid.get("components", [])
            matches = sum(1 for c in body.hwid.components if c in db_components)
            if matches < len(db_components) - 1:
                await write_audit("hwid.mismatch", user["uid"], {"hwid": body.hwid.combined_hash})
                from app.core.discord import notify_suspicious_login
                import asyncio
                asyncio.create_task(notify_suspicious_login(user["username"], 'HWID mismatch detected', client_ip, body.hwid.combined_hash))
                raise AppError("HWID_MISMATCH", "HWID mismatch detected.", 403)
                
    # Multi-Product Subscription verification
    subs_map = user.get("subscriptions") or {}
    requested_product = (body.product_id or "").strip()
    matched_sub = None

    if requested_product and isinstance(subs_map, dict) and subs_map:
        cand = subs_map.get(requested_product) or subs_map.get("global")
        if cand and cand.get("status") in ("active", "lifetime") and (cand.get("lifetime") or compute_days_left(cand) > 0):
            matched_sub = cand
        else:
            raise AppError("NO_SUBSCRIPTION", f"No active license found for product '{requested_product}'.", 403)
    elif isinstance(subs_map, dict) and subs_map:
        # Pick any active subscription if no specific product_id requested
        for pid, cand in subs_map.items():
            if isinstance(cand, dict) and cand.get("status") in ("active", "lifetime") and (cand.get("lifetime") or compute_days_left(cand) > 0):
                matched_sub = cand
                break
        if not matched_sub:
            raise AppError("NO_SUBSCRIPTION", "No active subscription.", 403)
    else:
        sub = user.get("subscription", {})
        sub_status = sub.get("status", "none")
        if sub_status not in ("active", "lifetime"):
            raise AppError("NO_SUBSCRIPTION", "No active subscription.", 403)
        if requested_product and requested_product not in ("default", "global") and sub.get("product_id") and sub.get("product_id") != requested_product:
            raise AppError("NO_SUBSCRIPTION", f"No active license found for product '{requested_product}'.", 403)
        matched_sub = {
            **sub,
            "product_id": sub.get("product_id") or requested_product or "default",
            "product_name": sub.get("product_name") or "Default Product",
        }

    matched_product_id = matched_sub.get("product_id") or requested_product or "default"
    matched_product_name = matched_sub.get("product_name") or "Default Product"
    sub_status = matched_sub.get("status", "active")
    days_left = compute_days_left(matched_sub)

    unlocked_products = [
        {
            "product_id": v.get("product_id") or k,
            "product_name": v.get("product_name") or k,
            "days_left": compute_days_left(v),
            "lifetime": bool(v.get("lifetime", False)),
        }
        for k, v in (subs_map.items() if isinstance(subs_map, dict) else [])
        if isinstance(v, dict) and v.get("status") in ("active", "lifetime") and (v.get("lifetime") or compute_days_left(v) > 0)
    ]
    if not unlocked_products:
        unlocked_products = [{
            "product_id": matched_product_id,
            "product_name": matched_product_name,
            "days_left": days_left,
            "lifetime": bool(matched_sub.get("lifetime", False)),
        }]

    # Session Creation & Per-Session Key Derivation
    server_priv, server_pub = generate_x25519_keypair()
    client_pub_bytes = bytes.fromhex(body.client_ephemeral_pub)
    derive_session_key(server_priv, client_pub_bytes, server_pub, client_pub_bytes)
    
    session_token = generate_loader_session_token()
    token_hash = hash_loader_session_token(session_token)
    resource_key = generate_resource_key(session_token, user["uid"])
    
    # Enforce max sessions
    max_sessions = s.max_sessions if hasattr(s, "max_sessions") else 1
    active_count = await db.count_active_loader_sessions(user["uid"])
    if active_count >= max_sessions:
        oldest = await db.get_oldest_loader_session(user["uid"])
        if oldest:
            await db.revoke_loader_session(oldest["session_id"])
            
    import uuid
    from datetime import timedelta
    await db.create_loader_session(
        session_id=str(uuid.uuid4()),
        uid=user["uid"],
        token_hash=token_hash,
        hwid_hash=body.hwid.combined_hash,
        ip=client_ip,
        app_version=body.build,
        expires_at=now + timedelta(hours=s.loader_session_ttl_hours)
    )
    
    resp_data = {
        "ok": True,
        "code": "OK",
        "session_token": session_token,
        "session_ttl": s.loader_session_ttl_hours * 3600,
        "heartbeat_interval": s.loader_heartbeat_interval_seconds,
        "server_time": int(now.timestamp()),
        "client_nonce": body.client_nonce,
        "server_ephemeral_pub": server_pub.hex(),
        "user": {
            "username": user["username"],
            "product_id": matched_product_id,
            "product_name": matched_product_name,
            "days_left": days_left,
            "expires_at": matched_sub.get("expires_at"),
            "unlocked_products": unlocked_products,
        },
        "subscription": {
            "status": sub_status,
            "product_id": matched_product_id,
            "product_name": matched_product_name,
            "days_left": days_left,
            "expires_at": matched_sub.get("expires_at"),
        },
        "resource_key": resource_key,
    }
    raw_bytes = json.dumps(resp_data, separators=(',', ':'), default=str).encode('utf-8')
    sig = sign_response(raw_bytes)
    return Response(content=raw_bytes, media_type="application/json", headers={"X-Signature": sig})

@router.post("/heartbeat")
async def loader_heartbeat(body: LoaderHeartbeatRequest, request: Request):
    db = request.state.db
    now = datetime.now(timezone.utc)
    
    is_unique = await db.check_and_store_nonce(body.nonce, ttl_seconds=120)
    if not is_unique:
        raise AppError("REPLAY_ATTACK", "Nonce reused.", 400)
        
    token_hash = hash_loader_session_token(body.session_token)
    session = await db.get_loader_session_by_token_hash(token_hash)
    
    if not session or session.get("revoked", False):
        raise InvalidSession()
        
    expires_at = session.get("expires_at")
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
    if expires_at and expires_at < now:
        raise InvalidSession()
        
    if body.seq <= session.get("last_seq", 0):
        raise InvalidSession()
        
    user = await db.get_user_by_uid(session["uid"])
    if not user:
        raise InvalidSession()
        
    directive = "none"
    message = "OK"
    days_left = compute_days_left(user.get("subscription", {}))
    sub_status = user.get("subscription", {}).get("status", "none")
    
    if user.get("banned", False) or sub_status not in ("active", "lifetime") or (sub_status == "active" and days_left == 0):
        directive = "terminate"
        message = "Subscription revoked or expired."
        
    await db.update_loader_session(session["session_id"], {"last_seq": body.seq, "last_heartbeat_at": now})
    
    resp_data = {
        "ok": True,
        "code": "OK",
        "days_left": days_left,
        "directive": directive,
        "message": message
    }
    raw_bytes = json.dumps(resp_data, separators=(',', ':'), default=str).encode('utf-8')
    sig = sign_response(raw_bytes)
    return Response(content=raw_bytes, media_type="application/json", headers={"X-Signature": sig})

@router.post("/logout")
async def loader_logout(body: LoaderLogoutRequest, request: Request):
    db = request.state.db
    token_hash = hash_loader_session_token(body.session_token)
    session = await db.get_loader_session_by_token_hash(token_hash)
    if session:
        await db.revoke_loader_session(session["session_id"])
    
    resp_data = {"ok": True, "code": "OK"}
    raw_bytes = json.dumps(resp_data, separators=(',', ':'), default=str).encode('utf-8')
    sig = sign_response(raw_bytes)
    return Response(content=raw_bytes, media_type="application/json", headers={"X-Signature": sig})
