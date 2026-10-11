"""
Client router: multi-product license redemption, subscription status,
HWID reset, loader download, and Lua Marketplace endpoints.
"""
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List

from fastapi import APIRouter, Request, Depends, Query, Path

from app.core.config import get_settings
from app.core.errors import (
    InvalidCredentials, Forbidden, NotFound, AppError,
    KeyAlreadyClaimed, KeyBanned, InvalidKey, HwidCooldown, NoSubscription
)
from app.core.security import (
    get_current_user_payload, get_current_uid, verify_password
)
from app.core.discord import notify_key_claimed, notify_hwid_reset
from app.core.crypto import compute_key_lookup
from app.core.audit import write_audit
from app.models.schemas import (
    RedeemKeyRequest, RedeemKeyResponse, HwidResetRequest,
    CreateScriptRequest, OkResponse, SubscriptionInfo
)

router = APIRouter(tags=["client"])


def _get_ip(request: Request) -> str:
    return request.headers.get("x-forwarded-for", request.client.host if request.client else "127.0.0.1").split(",")[0].strip()


def _parse_dt(val: Any) -> Optional[datetime]:
    if not val:
        return None
    if hasattr(val, "timestamp"):
        return datetime.fromtimestamp(val.timestamp(), tz=timezone.utc)
    if isinstance(val, datetime):
        return val.replace(tzinfo=timezone.utc) if val.tzinfo is None else val
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except Exception:
            return None
    return None


def _format_user_subscriptions(user: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build normalized list of active/unlocked product subscriptions for a user."""
    now = datetime.now(timezone.utc)
    subs_map = user.get("subscriptions") or {}
    out: List[Dict[str, Any]] = []

    if isinstance(subs_map, dict) and subs_map:
        for pid, sdata in subs_map.items():
            if not isinstance(sdata, dict):
                continue
            is_life = bool(sdata.get("lifetime", False))
            exp = _parse_dt(sdata.get("expires_at"))
            st = sdata.get("status", "none")
            if not is_life and exp and now > exp and st == "active":
                st = "expired"
            days_left = 99999 if is_life else (max(0, (exp - now).days) if (exp and st == "active") else 0)
            out.append({
                "product_id": sdata.get("product_id") or pid,
                "product_name": sdata.get("product_name") or pid,
                "status": st,
                "expires_at": exp,
                "days_left": days_left,
                "lifetime": is_life,
            })
    else:
        # Fallback to single subscription field if present
        sub = user.get("subscription") or {}
        if sub.get("status") in ("active", "expired"):
            is_life = bool(sub.get("lifetime", False))
            exp = _parse_dt(sub.get("expires_at"))
            st = sub.get("status", "none")
            if not is_life and exp and now > exp and st == "active":
                st = "expired"
            days_left = 99999 if is_life else (max(0, (exp - now).days) if (exp and st == "active") else 0)
            pid = sub.get("product_id") or "default"
            pname = sub.get("product_name") or "Default Product"
            out.append({
                "product_id": pid,
                "product_name": pname,
                "status": st,
                "expires_at": exp,
                "days_left": days_left,
                "lifetime": is_life,
            })

    return out


@router.get("/products")
async def get_public_products(request: Request):
    db = request.state.db
    items = await db.list_products()
    return {"ok": True, "items": items}


@router.post("/license/redeem", response_model=RedeemKeyResponse)
async def redeem_license(
    request: Request,
    body: RedeemKeyRequest,
    uid: str = Depends(get_current_uid)
) -> RedeemKeyResponse:
    db = request.state.db

    cleaned_key = body.key.strip().upper()
    if len(cleaned_key.split("-")) != 5:
        raise InvalidKey()

    lookup = compute_key_lookup(cleaned_key)
    license_doc = await db.get_license_by_lookup(lookup)

    if not license_doc:
        raise InvalidKey()

    status = license_doc.get("status")
    if status == "claimed":
        raise KeyAlreadyClaimed()
    elif status == "banned":
        raise KeyBanned()
    elif status in ("deleted", None):
        raise InvalidKey()
    elif status != "unused":
        raise InvalidKey()

    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")

    prod_id = license_doc.get("product_id") or "default"
    prod_name = license_doc.get("product_name")
    if not prod_name:
        pdoc = await db.get_product(prod_id)
        prod_name = pdoc.get("name") if pdoc else ("Default Product" if prod_id == "default" else prod_id)

    current_subs_map = dict(user.get("subscriptions") or {})
    current_prod_sub = current_subs_map.get(prod_id) or (
        user.get("subscription", {}) if prod_id == "default" and not current_subs_map else {}
    )

    now = datetime.now(timezone.utc)
    is_lifetime = bool(license_doc.get("lifetime", False))
    duration_days = license_doc.get("duration_days", 0) or 0
    fixed_expires_at = _parse_dt(license_doc.get("fixed_expires_at"))

    starts_at = now
    ends_at = None

    if not is_lifetime:
        if fixed_expires_at:
            ends_at = fixed_expires_at
        else:
            current_status = current_prod_sub.get("status")
            current_exp = _parse_dt(current_prod_sub.get("expires_at"))
            if current_status == "active" and current_exp and current_exp > now:
                starts_at = current_exp
                ends_at = current_exp + timedelta(days=duration_days)
            else:
                starts_at = now
                ends_at = now + timedelta(days=duration_days)

    # Atomic claim
    claimed = await db.claim_license_atomic(
        license_id=license_doc["id"],
        uid=uid,
        starts_at=starts_at,
        ends_at=ends_at
    )
    if not claimed:
        raise KeyAlreadyClaimed()

    # Update per-product subscription while preserving other unlocked products (Dual/Multi-product support)
    current_subs_map[prod_id] = {
        "product_id": prod_id,
        "product_name": prod_name,
        "status": "active",
        "expires_at": ends_at,
        "lifetime": is_lifetime,
    }

    # Also update summary subscription field
    sub_updates = {
        "status": "active",
        "expires_at": ends_at,
        "lifetime": is_lifetime,
        "product_id": prod_id,
        "product_name": prod_name,
    }
    await db.update_user(uid, {
        "subscription": sub_updates,
        "subscriptions": current_subs_map,
    })

    await write_audit(
        action="license.redeem",
        actor=uid,
        target=license_doc["id"],
        ip=_get_ip(request),
        meta={
            "key_prefix": license_doc.get("prefix"),
            "duration_days": duration_days,
            "lifetime": is_lifetime,
            "product_id": prod_id,
            "product_name": prod_name,
        }
    )

    await notify_key_claimed(
        username=user.get("username", "Unknown"),
        prefix=license_doc.get("prefix", "UNK"),
        duration_label="Lifetime" if is_lifetime else f"{duration_days} Days ({prod_name})",
        discord_id=user.get("discord_id"),
        ip=_get_ip(request)
    )

    days_left = None
    if is_lifetime:
        days_left = 99999
    elif ends_at:
        days_left = max(0, (ends_at - now).days)

    updated_user = await db.get_user_by_uid(uid)
    formatted_subs = _format_user_subscriptions(updated_user or user)

    return RedeemKeyResponse(
        ok=True,
        days_added=None if is_lifetime else duration_days,
        days_left=days_left,
        expires_at=ends_at,
        lifetime=is_lifetime,
        product_id=prod_id,
        product_name=prod_name,
        subscriptions=formatted_subs,
    )


@router.get("/subscription", response_model=Dict[str, Any])
async def get_subscription(
    request: Request,
    uid: str = Depends(get_current_uid)
) -> Dict[str, Any]:
    db = request.state.db
    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")

    sub = user.get("subscription", {})
    now = datetime.now(timezone.utc)
    status = sub.get("status", "none")
    expires_at = _parse_dt(sub.get("expires_at"))
    is_lifetime = bool(sub.get("lifetime", False))

    if not is_lifetime and expires_at:
        if now > expires_at and status == "active":
            status = "expired"
            await db.update_user(uid, {"subscription": {**sub, "status": "expired"}})

    days_left = None
    if is_lifetime:
        days_left = 99999
    elif expires_at and status == "active":
        days_left = max(0, (expires_at - now).days)

    formatted_subs = _format_user_subscriptions(user)
    active_products = [s for s in formatted_subs if s.get("status") == "active"]
    if active_products and status != "active":
        status = "active"
        primary = active_products[0]
        expires_at = primary.get("expires_at")
        days_left = primary.get("days_left")
        is_lifetime = primary.get("lifetime", False)

    return {
        "ok": True,
        "subscription": {
            "status": status,
            "expires_at": expires_at,
            "days_left": days_left,
            "lifetime": is_lifetime,
            "product_id": sub.get("product_id"),
            "product_name": sub.get("product_name"),
            "subscriptions": formatted_subs,
        },
        "subscriptions": formatted_subs,
    }


@router.post("/hwid/reset", response_model=Dict[str, Any])
async def reset_hwid(
    request: Request,
    body: HwidResetRequest,
    uid: str = Depends(get_current_uid)
) -> Dict[str, Any]:
    db = request.state.db
    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")

    if user.get("username", "").lower() != body.username.lower():
        raise InvalidCredentials()

    if not verify_password(body.password, user.get("password_hash", "")):
        raise InvalidCredentials()

    settings = await db.get_settings()
    cooldown_days = settings.get("hwid_reset_cooldown_days", 7)

    hwid_data = user.get("hwid", {})
    last_reset = _parse_dt(hwid_data.get("last_reset_at"))

    now = datetime.now(timezone.utc)
    if last_reset:
        elapsed = (now - last_reset).days
        if elapsed < cooldown_days:
            raise HwidCooldown(cooldown_days - elapsed)

    new_hwid = {
        "combined_hash": None,
        "components": [],
        "bound_at": None,
        "last_reset_at": now
    }

    await db.update_user(uid, {"hwid": new_hwid})
    await db.revoke_user_loader_sessions(uid)

    await write_audit(
        action="hwid.reset",
        actor=uid,
        target=uid,
        ip=_get_ip(request),
        meta={}
    )

    await notify_hwid_reset(
        target_username=user.get("username", "Unknown"),
        actor_username=user.get("username", "Unknown"),
        actor_is_admin=False,
        ip=_get_ip(request)
    )

    return {
        "ok": True,
        "message": "HWID reset successfully. You may now log in on your new hardware."
    }


@router.get("/loader/latest", response_model=Dict[str, Any])
async def get_latest_loader(
    request: Request,
    uid: str = Depends(get_current_uid)
) -> Dict[str, Any]:
    db = request.state.db
    settings = await db.get_settings()

    if settings.get("loader_download_requires_subscription", False):
        user = await db.get_user_by_uid(uid)
        sub = user.get("subscription", {})
        if sub.get("status") != "active":
            raise NoSubscription()

    release = await db.get_active_release()
    if not release:
        return {
            "ok": True,
            "version": settings.get("current_loader_version", "1.0.0"),
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "download_url": "/api/v1/loader/status?app_id=pruvate_loader_v1",
            "changelog": "Initial release with X25519 + Ed25519 + Dual-Product Auth."
        }

    return {
        "ok": True,
        "version": release.get("version"),
        "sha256": release.get("sha256"),
        "download_url": f"/api/v1/loader/download/{release.get('version')}",
        "changelog": release.get("changelog", "")
    }


# ===========================================================================
# LUA MARKETPLACE ENDPOINTS
# ===========================================================================

@router.get("/scripts")
async def list_marketplace_scripts(
    request: Request,
    search: Optional[str] = Query(default=None),
    tag: Optional[str] = Query(default=None),
    sort: str = Query(default="new"),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=24, ge=1, le=100),
):
    db = request.state.db
    items, total = await db.list_scripts(search=search, tag=tag, sort=sort, status="published", page=page, limit=limit)
    return {"ok": True, "items": items, "total": total, "page": page, "limit": limit}


@router.get("/scripts/{script_id}")
async def get_marketplace_script(
    request: Request,
    script_id: str = Path(...),
):
    db = request.state.db
    script = await db.get_script(script_id)
    if not script or script.get("status") == "deleted":
        raise NotFound("Script")
    return {"ok": True, "script": script}


@router.post("/scripts", status_code=201)
async def create_marketplace_script(
    request: Request,
    body: CreateScriptRequest,
    uid: str = Depends(get_current_uid),
):
    db = request.state.db
    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")

    title = (body.title or body.name or "Untitled Script").strip()
    now = datetime.now(timezone.utc)
    clean_tags = [t.strip() for t in (body.tags or []) if t.strip()][:8]

    script_data = {
        "title": title,
        "name": title,
        "description": body.description.strip(),
        "code": body.code,
        "tags": clean_tags,
        "product_id": body.product_id or "default",
        "cover_url": body.cover_url or None,
        "author_uid": uid,
        "author_username": user.get("username", "User"),
        "status": "published",
        "downloads": 0,
        "likes": 0,
        "reports": 0,
        "created_at": now,
        "updated_at": now,
    }
    script_id = await db.create_script(script_data)
    script_data["id"] = script_id

    await write_audit(
        action="script.create",
        actor=uid,
        target=script_id,
        ip=_get_ip(request),
        meta={"title": title, "product_id": script_data["product_id"]},
    )
    return {"ok": True, "script": script_data, "id": script_id}


@router.delete("/scripts/{script_id}")
async def delete_marketplace_script(
    request: Request,
    script_id: str = Path(...),
    uid: str = Depends(get_current_uid),
):
    db = request.state.db
    script = await db.get_script(script_id)
    if not script:
        raise NotFound("Script")
    user = await db.get_user_by_uid(uid)
    if script.get("author_uid") != uid and not (user and user.get("admin")):
        raise Forbidden()

    await db.update_script(script_id, {"status": "deleted", "updated_at": datetime.now(timezone.utc)})
    return {"ok": True}


@router.post("/scripts/{script_id}/like")
async def like_marketplace_script(
    request: Request,
    script_id: str = Path(...),
    uid: str = Depends(get_current_uid),
):
    db = request.state.db
    script = await db.get_script(script_id)
    if not script or script.get("status") == "deleted":
        raise NotFound("Script")
    likes = int(script.get("likes", 0)) + 1
    await db.update_script(script_id, {"likes": likes})
    return {"ok": True, "likes": likes}


@router.post("/scripts/{script_id}/download")
async def download_marketplace_script(
    request: Request,
    script_id: str = Path(...),
):
    db = request.state.db
    script = await db.get_script(script_id)
    if not script or script.get("status") == "deleted":
        raise NotFound("Script")
    downloads = int(script.get("downloads", 0)) + 1
    await db.update_script(script_id, {"downloads": downloads})
    return {"ok": True, "downloads": downloads, "code": script.get("code", "")}
