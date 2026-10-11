"""
Admin router: user, license, script, API key management.
"""
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, Request, Depends, Query, Path

from app.core.config import get_settings
from app.core.errors import (
    Forbidden, NotFound, AppError
)
from app.core.security import (
    get_current_uid, hash_password
)
from app.core.discord import (
    notify_key_generated, notify_ban, notify_hwid_reset
)
from app.core.crypto import encrypt_license_key, decrypt_license_key, compute_key_lookup
from app.core.audit import write_audit
from app.models.schemas import (
    OkResponse, CreateProductRequest, GenerateLicensesRequest, BanRequest, AddDaysRequest,
    AdminChangeEmailRequest, AdminChangePasswordRequest, UpdateSettingsRequest,
    CreateAnnouncementRequest, CreateApiKeyRequest
)

router = APIRouter(tags=["admin"])

def _get_ip(request: Request) -> str:
    return request.headers.get("x-forwarded-for", request.client.host if request.client else "127.0.0.1").split(",")[0].strip()

async def verify_admin(request: Request, uid: str = Depends(get_current_uid)) -> str:
    db = request.state.db
    user = await db.get_user_by_uid(uid)
    if not user or user.get("admin") is not True:
        raise Forbidden()
    return uid

async def recalculate_user_subscription(db, uid: str):
    valid_licenses = await db.get_user_active_licenses(uid)
    now = datetime.now(timezone.utc)

    if not valid_licenses:
        await db.update_user(uid, {
            "subscription": {"status": "disabled", "expires_at": None, "lifetime": False, "product_id": None, "product_name": None},
            "subscriptions": {},
        })
        return

    # Group valid licenses by product_id
    by_product: Dict[str, List[Dict[str, Any]]] = {}
    for l in valid_licenses:
        pid = l.get("product_id") or "default"
        by_product.setdefault(pid, []).append(l)

    subscriptions_map: Dict[str, Dict[str, Any]] = {}
    overall_lifetime = False
    overall_max_expiry = None
    primary_pid = None
    primary_pname = None

    for pid, lics in by_product.items():
        pname = lics[-1].get("product_name") or pid
        prod_lifetime = any(x.get("lifetime", False) for x in lics)
        if prod_lifetime:
            subscriptions_map[pid] = {
                "product_id": pid,
                "product_name": pname,
                "status": "active",
                "expires_at": None,
                "lifetime": True,
            }
            overall_lifetime = True
            primary_pid = pid
            primary_pname = pname
        else:
            prod_max = None
            for x in lics:
                ends = x.get("ends_at")
                if ends:
                    if hasattr(ends, "timestamp"):
                        ends = datetime.fromtimestamp(ends.timestamp(), tz=timezone.utc)
                    elif isinstance(ends, datetime) and ends.tzinfo is None:
                        ends = ends.replace(tzinfo=timezone.utc)
                    if not prod_max or ends > prod_max:
                        prod_max = ends
            if prod_max and prod_max > now:
                subscriptions_map[pid] = {
                    "product_id": pid,
                    "product_name": pname,
                    "status": "active",
                    "expires_at": prod_max,
                    "lifetime": False,
                }
                if not overall_max_expiry or prod_max > overall_max_expiry:
                    overall_max_expiry = prod_max
                    if not overall_lifetime:
                        primary_pid = pid
                        primary_pname = pname

    if overall_lifetime:
        await db.update_user(uid, {
            "subscription": {
                "status": "active",
                "expires_at": None,
                "lifetime": True,
                "product_id": primary_pid,
                "product_name": primary_pname,
            },
            "subscriptions": subscriptions_map,
        })
    elif overall_max_expiry:
        await db.update_user(uid, {
            "subscription": {
                "status": "active",
                "expires_at": overall_max_expiry,
                "lifetime": False,
                "product_id": primary_pid,
                "product_name": primary_pname,
            },
            "subscriptions": subscriptions_map,
        })
    else:
        await db.update_user(uid, {
            "subscription": {"status": "disabled", "expires_at": None, "lifetime": False, "product_id": None, "product_name": None},
            "subscriptions": {},
        })

# -----------------
# Products
# -----------------
@router.get("/products")
async def list_products(request: Request, admin_uid: str = Depends(verify_admin)):
    db = request.state.db
    items = await db.list_products()
    return {"ok": True, "items": items}

@router.post("/products", status_code=201)
async def create_product(
    request: Request,
    body: CreateProductRequest,
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    prod = await db.create_product(
        product_id=body.product_id.strip(),
        name=body.name.strip(),
        description=(body.description or "").strip(),
    )
    await write_audit(
        action="admin.product_create",
        actor=admin_uid,
        target=body.product_id,
        ip=_get_ip(request),
        meta={"product_id": body.product_id, "name": body.name},
    )
    return {"ok": True, "product": prod}

@router.delete("/products/{product_id}")
async def delete_product(
    request: Request,
    product_id: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    await db.delete_product(product_id)
    await write_audit(
        action="admin.product_delete",
        actor=admin_uid,
        target=product_id,
        ip=_get_ip(request),
        meta={"product_id": product_id},
    )
    return {"ok": True}

# -----------------
# Licenses
# -----------------
@router.post("/licenses/generate")
async def generate_licenses(
    request: Request,
    body: GenerateLicensesRequest,
    admin_uid: str = Depends(verify_admin)
) -> Dict[str, Any]:
    db = request.state.db
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    keys = []

    prod_id = (body.product_id or "default").strip()
    prod_name = body.product_name
    if not prod_name:
        prod_doc = await db.get_product(prod_id)
        prod_name = prod_doc.get("name") if prod_doc else ("Default Product" if prod_id == "default" else prod_id)

    for _ in range(body.quantity):
        segments = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4)]
        raw_key = f"{body.prefix}-" + "-".join(segments) if body.prefix else "-".join(segments)
        
        enc_key = encrypt_license_key(raw_key)
        lookup = compute_key_lookup(raw_key)
        
        import uuid
        lic_id = str(uuid.uuid4())
        await db.create_license(
            license_id=lic_id,
            key_lookup=lookup,
            key_enc=enc_key,
            prefix=body.prefix,
            duration_days=body.duration_days,
            fixed_expires_at=body.fixed_expires_at,
            lifetime=body.lifetime,
            discord_id=body.discord_id,
            note=body.note,
            batch_id=str(uuid.uuid4()),
            created_by=admin_uid,
            product_id=prod_id,
            product_name=prod_name,
        )
        keys.append(raw_key)
        
    admin_user = await db.get_user_by_uid(admin_uid)
    await write_audit(
        action="admin.licenses_generate",
        actor=admin_uid,
        target=None,
        ip=_get_ip(request),
        meta={
            "quantity": body.quantity,
            "prefix": body.prefix,
            "duration_days": body.duration_days,
            "lifetime": body.lifetime,
            "product_id": prod_id,
            "product_name": prod_name,
        },
    )
    
    await notify_key_generated(
        admin_username=admin_user.get("username", "Admin"),
        count=body.quantity,
        prefix=body.prefix,
        duration_label="Lifetime" if body.lifetime else f"{body.duration_days} Days"
    )
    
    return {"ok": True, "count": len(keys), "keys": keys, "product_id": prod_id, "product_name": prod_name}

@router.get("/licenses")
async def list_licenses(
    request: Request,
    status: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    docs, total = await db.list_licenses(status=status, page=page, limit=page_size)
    for d in docs:
        enc = d.get("key_enc") or d.get("encrypted_key")
        if enc:
            try:
                d["raw_key"] = decrypt_license_key(enc)
            except Exception:
                pass
    return {"ok": True, "items": docs}

@router.get("/licenses/{license_id}")
async def get_license(
    request: Request,
    license_id: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    doc = await db.get_license_by_id(license_id)
    if not doc:
        raise NotFound("License")
    enc = doc.get("key_enc") or doc.get("encrypted_key")
    if enc:
        doc["raw_key"] = decrypt_license_key(enc)
    return {"ok": True, "license": doc}

@router.post("/licenses/{license_id}/ban")
async def ban_license(
    request: Request,
    body: BanRequest,
    license_id: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    doc = await db.get_license_by_id(license_id)
    if not doc:
        raise NotFound("License")
        
    await db.update_license(license_id, {"status": "banned", "ban_reason": body.reason})
    
    claimed_by = doc.get("claimed_by")
    if claimed_by:
        await recalculate_user_subscription(db, claimed_by)
        await db.revoke_user_loader_sessions(claimed_by)
        
    admin_user = await db.get_user_by_uid(admin_uid)
    await write_audit(action="admin.license_ban", actor=admin_uid, target=license_id, ip=_get_ip(request), meta={"reason": body.reason}
    )
    
    await notify_ban(
        target_username=f"License {license_id}",
        actor_username=admin_user.get("username", "Admin"),
        reason=body.reason,
        target_type="license"
    )
    
    return {"ok": True}

@router.post("/licenses/{license_id}/unban")
async def unban_license(
    request: Request,
    license_id: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    doc = await db.get_license_by_id(license_id)
    if not doc:
        raise NotFound("License")
        
    new_status = "claimed" if doc.get("claimed_by") else "unused"
    await db.update_license(license_id, {"status": new_status, "ban_reason": None})
    
    if doc.get("claimed_by"):
        await recalculate_user_subscription(db, doc["claimed_by"])
        
    return {"ok": True}

@router.delete("/licenses/{license_id}")
async def delete_license(
    request: Request,
    license_id: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    doc = await db.get_license_by_id(license_id)
    if not doc:
        raise NotFound("License")
        
    await db.update_license(license_id, {"status": "deleted"})
    if doc.get("claimed_by"):
        await recalculate_user_subscription(db, doc["claimed_by"])
        await db.revoke_user_loader_sessions(doc["claimed_by"])
        
    return {"ok": True}

# -----------------
# Users
# -----------------
@router.get("/users")
async def list_users(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    docs, total = await db.list_users(page=page, limit=page_size)
    return {"ok": True, "items": docs}

@router.get("/users/{uid}")
async def get_user_details(
    request: Request,
    uid: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    doc = await db.get_user_by_uid(uid)
    if not doc:
        raise NotFound("User")
    return {"ok": True, "user": doc}

@router.patch("/users/{uid}/email")
async def update_user_email(
    request: Request,
    body: AdminChangeEmailRequest,
    uid: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    doc = await db.get_user_by_uid(uid)
    if not doc:
        raise NotFound("User")
        
    await db.update_user(uid, {"email": body.new_email, "email_verified": False})
    return {"ok": True}

@router.patch("/users/{uid}/password")
async def update_user_password(
    request: Request,
    body: AdminChangePasswordRequest,
    uid: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    doc = await db.get_user_by_uid(uid)
    if not doc:
        raise NotFound("User")
        
    new_hash = hash_password(body.new_password)
    tv = doc.get("token_version", 0) + 1
    await db.update_user(uid, {"password_hash": new_hash, "token_version": tv})
    await db.revoke_all_web_sessions(uid)
    await db.revoke_user_loader_sessions(uid)
    return {"ok": True}

@router.post("/users/{uid}/ban")
async def ban_user(
    request: Request,
    body: BanRequest,
    uid: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    doc = await db.get_user_by_uid(uid)
    if not doc:
        raise NotFound("User")
        
    await db.update_user(uid, {"banned": True, "ban_reason": body.reason})
    await db.revoke_all_web_sessions(uid)
    await db.revoke_user_loader_sessions(uid)
    
    admin_user = await db.get_user_by_uid(admin_uid)
    await write_audit(action="admin.user_ban", actor=admin_uid, target=uid, ip=_get_ip(request), meta={"reason": body.reason}
    )
    
    await notify_ban(
        target_username=doc.get("username", "Unknown"),
        actor_username=admin_user.get("username", "Admin"),
        reason=body.reason,
        target_type="user"
    )
    return {"ok": True}

@router.post("/users/{uid}/unban")
async def unban_user(
    request: Request,
    uid: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    doc = await db.get_user_by_uid(uid)
    if not doc:
        raise NotFound("User")
        
    await db.update_user(uid, {"banned": False, "ban_reason": None})
    return {"ok": True}

@router.post("/users/{uid}/force-logout")
async def force_logout(
    request: Request,
    uid: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    doc = await db.get_user_by_uid(uid)
    if not doc:
        raise NotFound("User")
        
    tv = doc.get("token_version", 0) + 1
    await db.update_user(uid, {"token_version": tv})
    await db.revoke_all_web_sessions(uid)
    await db.revoke_user_loader_sessions(uid)
    return {"ok": True}

@router.post("/users/{uid}/hwid-reset")
async def admin_hwid_reset(
    request: Request,
    uid: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")
        
    new_hwid = {
        "combined_hash": None,
        "components": [],
        "bound_at": None,
        "last_reset_at": datetime.now(timezone.utc)
    }
    await db.update_user(uid, {"hwid": new_hwid})
    await db.revoke_user_loader_sessions(uid)
    
    admin_user = await db.get_user_by_uid(admin_uid)
    await notify_hwid_reset(
        target_username=user.get("username", "Unknown"),
        actor_username=admin_user.get("username", "Admin"),
        actor_is_admin=True,
        ip=_get_ip(request)
    )
    return {"ok": True}

@router.post("/users/{uid}/add-days")
async def add_days(
    request: Request,
    body: AddDaysRequest,
    uid: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")
        
    sub = user.get("subscription", {})
    sub_status = sub.get("status")
    current_expires = sub.get("expires_at")
    
    if sub.get("lifetime"):
        return {"ok": True, "message": "User has lifetime subscription"}
        
    now = datetime.now(timezone.utc)
    if sub_status == "active" and current_expires and current_expires > now:
        new_expires = current_expires + timedelta(days=body.days)
    else:
        new_expires = now + timedelta(days=body.days)
        
    await db.update_user(uid, {"subscription": {"status": "active", "expires_at": new_expires, "lifetime": False}})
    return {"ok": True, "expires_at": new_expires}

@router.post("/users/{uid}/remove-days")
async def remove_days(
    request: Request,
    body: AddDaysRequest,
    uid: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")
        
    sub = user.get("subscription", {})
    current_expires = sub.get("expires_at")
    
    if sub.get("lifetime"):
        return {"ok": True, "message": "User has lifetime subscription"}
        
    if current_expires:
        new_expires = current_expires - timedelta(days=body.days)
        now = datetime.now(timezone.utc)
        if new_expires <= now:
            await db.update_user(uid, {"subscription": {"status": "disabled", "expires_at": None, "lifetime": False}})
            return {"ok": True, "status": "disabled"}
        else:
            await db.update_user(uid, {"subscription": {"status": "active", "expires_at": new_expires, "lifetime": False}})
            return {"ok": True, "expires_at": new_expires}
            
    return {"ok": True}

# -----------------
# Admin Stats/Other
# -----------------
@router.get("/stats")
async def get_stats(request: Request, admin_uid: str = Depends(verify_admin)):
    db = request.state.db
    stats = await db.get_stats()
    return {"ok": True, "stats": stats}

@router.get("/audit-log")
async def list_audit_logs(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    logs, total = await db.list_audit_logs(page=page, limit=page_size)
    return {"ok": True, "items": logs}

@router.get("/announcements")
async def list_announcements(request: Request, admin_uid: str = Depends(verify_admin)):
    db = request.state.db
    items = await db.list_announcements(active_only=False)
    return {"ok": True, "items": items}

@router.post("/announcements")
async def create_announcement(
    request: Request,
    body: CreateAnnouncementRequest,
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    ann_id = await db.create_announcement(body.dict())
    return {"ok": True, "id": ann_id}

@router.patch("/announcements/{ann_id}")
async def update_announcement(
    request: Request,
    body: Dict[str, Any],
    ann_id: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    await db.update_announcement(ann_id, body)
    return {"ok": True}

@router.delete("/announcements/{ann_id}")
async def delete_announcement(
    request: Request,
    ann_id: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    await db.delete_announcement(ann_id)
    return {"ok": True}

@router.get("/settings")
async def get_settings_admin(request: Request, admin_uid: str = Depends(verify_admin)):
    db = request.state.db
    settings = await db.get_settings()
    return {"ok": True, "settings": settings}

@router.patch("/settings")
async def update_settings(
    request: Request,
    body: UpdateSettingsRequest,
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    await db.update_settings(body.dict(exclude_unset=True))
    return {"ok": True}

@router.get("/api-keys")
async def list_api_keys(request: Request, admin_uid: str = Depends(verify_admin)):
    db = request.state.db
    keys = await db.list_api_keys()
    return {"ok": True, "items": keys}

@router.post("/api-keys")
async def create_api_key(
    request: Request,
    body: CreateApiKeyRequest,
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    key_id = await db.create_api_key(body.dict())
    return {"ok": True, "id": key_id}

@router.delete("/api-keys/{key_id}")
async def delete_api_key(
    request: Request,
    key_id: str = Path(...),
    admin_uid: str = Depends(verify_admin)
):
    db = request.state.db
    await db.update_api_key(key_id, {"is_active": False})
    return {"ok": True}

@router.get("/anomalies")
async def list_anomalies(request: Request, admin_uid: str = Depends(verify_admin)):
    # This would typically be a specific DB call.
    return {"ok": True, "items": []}
