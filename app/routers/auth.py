"""
Authentication router: register, login, refresh, logout, password reset,
email verification, TOTP, session management.
"""
import hashlib
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

from fastapi import APIRouter, Request, Response, Depends
from fastapi.responses import JSONResponse
import pyotp
import qrcode
import io
import base64

from app.core.config import get_settings
from app.core.errors import (
    InvalidCredentials, UserBanned, EmailNotVerified, TotpRequired, TotpInvalid,
    NotFound, InternalError, CaptchaFailed, Forbidden, InvalidSession,
)
from app.core.security import (
    hash_password, verify_password, needs_rehash,
    create_access_token, create_refresh_token, create_email_verify_token,
    create_password_reset_token, decode_token,
    set_auth_cookies, clear_auth_cookies, generate_csrf_token,
    get_current_user_payload, get_current_uid,
    hash_refresh_token, generate_loader_session_token,
    EMAIL_VERIFY_TOKEN_TYPE, PASSWORD_RESET_TOKEN_TYPE,
    ACCESS_TOKEN_TYPE, constant_time_compare,
)
from app.core.audit import write_audit
from app.core.email import send_verification_email, send_password_reset_email
from app.core.rate_limit import (
    limiter, check_lockout, record_failed_attempt, clear_failed_attempts,
    verify_turnstile,
)
from app.models.schemas import (
    RegisterRequest, LoginRequest, ForgotPasswordRequest, ResetPasswordRequest,
    ChangePasswordRequest, ChangeEmailRequest, VerifyEmailRequest,
    TotpEnableRequest, TotpDisableRequest,
    UserResponse, LoginResponse, SubscriptionInfo, HwidInfo, OkResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _get_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _compute_days_left(sub: Dict) -> Optional[int]:
    expires_at = sub.get("expires_at")
    if not expires_at:
        return None
    if hasattr(expires_at, 'timestamp'):
        exp = datetime.fromtimestamp(expires_at.timestamp(), tz=timezone.utc)
    elif isinstance(expires_at, datetime):
        if expires_at.tzinfo is None:
            exp = expires_at.replace(tzinfo=timezone.utc)
        else:
            exp = expires_at
    else:
        return None
    delta = exp - datetime.now(timezone.utc)
    return max(0, delta.days)


def _build_user_response(user: Dict) -> UserResponse:
    from app.routers.client import _format_user_subscriptions
    sub = user.get("subscription", {})
    hwid = user.get("hwid", {})
    subs_list = _format_user_subscriptions(user)
    return UserResponse(
        uid=user["uid"],
        username=user["username"],
        email=user["email"],
        admin=user.get("admin", False),
        email_verified=user.get("email_verified", False),
        totp_enabled=user.get("totp_enabled", False),
        subscription=SubscriptionInfo(
            status=sub.get("status", "none"),
            expires_at=sub.get("expires_at"),
            days_left=_compute_days_left(sub),
            lifetime=bool(sub.get("lifetime", False)),
            product_id=sub.get("product_id"),
            product_name=sub.get("product_name"),
        ),
        subscriptions=subs_list,
        hwid=HwidInfo(
            bound=bool(hwid.get("combined_hash")),
            bound_at=hwid.get("bound_at"),
            last_reset_at=hwid.get("last_reset_at"),
        ),
        created_at=user["created_at"],
        last_login_at=user.get("last_login_at"),
    )


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------
@router.post("/register", status_code=201)
@limiter.limit("5/minute")
async def register(request: Request, body: RegisterRequest, response: Response):
    s = get_settings()
    ip = _get_ip(request)
    db = request.state.db

    # Turnstile CAPTCHA verification
    if s.turnstile_secret_key and not await verify_turnstile(body.turnstile_token, ip):
        raise CaptchaFailed()

    # Check registration open
    settings = await db.get_settings()
    if not settings.get("registration_open", True):
        from app.core.errors import AppError
        raise AppError("REGISTRATION_CLOSED", "Registration is currently closed.", 403)

    # Hash password
    password_hash = hash_password(body.password)
    uid = str(uuid.uuid4())

    # Create user (raises UsernameTaken / EmailTaken on conflict)
    user = await db.create_user(
        uid=uid,
        username=body.username,
        email=body.email.lower().strip(),
        password_hash=password_hash,
    )

    # Send verification email
    verify_token = create_email_verify_token(uid, user["email"])
    token_hash = hashlib.sha256(verify_token.encode()).hexdigest()
    await db.store_token(
        token_type=EMAIL_VERIFY_TOKEN_TYPE,
        uid=uid,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=s.email_verify_ttl_hours),
        extra={"email": user["email"]},
    )
    await send_verification_email(user["email"], body.username, verify_token)

    await write_audit(
        action="user.register",
        actor=uid,
        target=uid,
        ip=ip,
        meta={"username": body.username, "email": user["email"]},
    )

    return {"ok": True, "message": "Account created. Please verify your email address."}


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------
@router.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest, response: Response):
    s = get_settings()
    ip = _get_ip(request)
    db = request.state.db

    # Progressive lockout check
    await check_lockout(ip)
    await check_lockout(body.identifier.lower())

    # Look up user — generic error regardless of failure reason
    user = await db.get_user_by_identifier(body.identifier)
    if not user:
        await record_failed_attempt(ip)
        await record_failed_attempt(body.identifier.lower())
        raise InvalidCredentials()

    if not verify_password(body.password, user.get("password_hash", "")):
        await record_failed_attempt(ip)
        await record_failed_attempt(body.identifier.lower())
        await write_audit(
            action="user.login_failed",
            actor=user["uid"],
            target=user["uid"],
            ip=ip,
            meta={"reason": "wrong_password"},
        )
        raise InvalidCredentials()

    if user.get("banned"):
        raise UserBanned(user.get("ban_reason", ""))

    if not user.get("email_verified", False) and bool(s.smtp_host):
        raise EmailNotVerified()

    # TOTP check
    if user.get("totp_enabled") and user.get("totp_secret_enc"):
        if not body.totp_code:
            raise TotpRequired()
        from app.core.crypto import decrypt_license_key  # reuse AES-GCM
        try:
            totp_secret = decrypt_license_key(user["totp_secret_enc"])
        except Exception:
            raise InternalError()
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(body.totp_code, valid_window=1):
            await record_failed_attempt(ip)
            raise TotpInvalid()

    # Rehash if needed
    if needs_rehash(user["password_hash"]):
        new_hash = hash_password(body.password)
        await db.update_user(user["uid"], {"password_hash": new_hash})

    # Clear lockout on success
    await clear_failed_attempts(ip)
    await clear_failed_attempts(body.identifier.lower())

    # Create tokens
    token_version = user.get("token_version", 1)
    access_token = create_access_token(user["uid"], token_version)
    raw_refresh, refresh_hash = create_refresh_token()
    csrf = generate_csrf_token()
    family_id = str(uuid.uuid4())

    user_agent = request.headers.get("User-Agent", "")[:255]
    await db.create_web_session(
        uid=user["uid"],
        token_hash=refresh_hash,
        ip=ip,
        user_agent=user_agent,
        family_id=family_id,
    )

    # Update last login
    await db.update_user(user["uid"], {
        "last_login_at": datetime.now(timezone.utc),
        "last_login_ip": ip,
    })

    await write_audit(
        action="user.login",
        actor=user["uid"],
        target=user["uid"],
        ip=ip,
        meta={"username": user["username"]},
    )

    set_auth_cookies(response, access_token, raw_refresh, csrf)
    return LoginResponse(
        user=_build_user_response({**user}),
        csrf_token=csrf,
    ).model_dump()


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------
@router.post("/refresh")
async def refresh_token(request: Request, response: Response):
    from fastapi import Cookie
    raw_refresh = request.cookies.get("refresh_token")
    if not raw_refresh:
        raise InvalidSession()

    ip = _get_ip(request)
    db = request.state.db

    token_hash = hash_refresh_token(raw_refresh)
    session = await db.get_web_session_by_token_hash(token_hash)
    if not session:
        # Possible reuse attack — check family
        raise InvalidSession()

    # Check token reuse within the family
    reuse = await db.detect_refresh_token_reuse(session["family_id"], token_hash)
    if reuse:
        # Revoke entire family
        await db.revoke_all_web_sessions(session["uid"])
        await write_audit(
            action="user.refresh_token_reuse",
            actor=session["uid"],
            ip=ip,
            meta={"family_id": session["family_id"]},
        )
        raise InvalidSession()

    # Check session expiry
    expires_at = session.get("expires_at")
    if expires_at:
        if hasattr(expires_at, 'timestamp'):
            exp_dt = datetime.fromtimestamp(expires_at.timestamp(), tz=timezone.utc)
        elif isinstance(expires_at, datetime):
            exp_dt = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
        else:
            exp_dt = None
        if exp_dt and datetime.now(timezone.utc) > exp_dt:
            raise InvalidSession()

    # Get user and check token_version
    user = await db.get_user_by_uid(session["uid"])
    if not user or user.get("banned"):
        raise InvalidSession()

    # Rotate refresh token
    new_raw, new_hash = create_refresh_token()
    new_csrf = generate_csrf_token()
    await db.rotate_web_session(session["session_id"], new_hash, ip)

    token_version = user.get("token_version", 1)
    new_access = create_access_token(user["uid"], token_version)

    set_auth_cookies(response, new_access, new_raw, new_csrf)
    return {"ok": True, "csrf_token": new_csrf}


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------
@router.post("/logout")
async def logout(request: Request, response: Response):
    raw_refresh = request.cookies.get("refresh_token")
    raw_access = request.cookies.get("access_token")
    db = request.state.db
    ip = _get_ip(request)

    if raw_refresh:
        token_hash = hash_refresh_token(raw_refresh)
        session = await db.get_web_session_by_token_hash(token_hash)
        if session:
            await db.revoke_web_session(session["session_id"])
            await write_audit(
                action="user.logout",
                actor=session["uid"],
                ip=ip,
            )
    elif raw_access:
        try:
            payload = decode_token(raw_access, ACCESS_TOKEN_TYPE)
            uid = payload.get("sub")
            if uid:
                await db.revoke_all_web_sessions(uid)
                await write_audit(action="user.logout", actor=uid, ip=ip)
        except Exception:
            pass

    clear_auth_cookies(response)
    return {"ok": True}


# ---------------------------------------------------------------------------
# POST /auth/logout-all
# ---------------------------------------------------------------------------
@router.post("/logout-all")
async def logout_all(
    request: Request,
    response: Response,
    payload: Dict[str, Any] = Depends(get_current_user_payload),
):
    uid = payload["sub"]
    db = request.state.db
    ip = _get_ip(request)

    # Increment token_version to invalidate all existing access tokens
    user = await db.get_user_by_uid(uid)
    current_version = user.get("token_version", 1) if user else 1
    await db.update_user(uid, {"token_version": current_version + 1})
    await db.revoke_all_web_sessions(uid)

    await write_audit(action="user.logout_all", actor=uid, ip=ip)

    clear_auth_cookies(response)
    return {"ok": True}


# ---------------------------------------------------------------------------
# POST /auth/forgot-password
# ---------------------------------------------------------------------------
@router.post("/forgot-password")
@limiter.limit("3/minute")
async def forgot_password(request: Request, body: ForgotPasswordRequest):
    s = get_settings()
    ip = _get_ip(request)
    db = request.state.db

    if s.turnstile_secret_key and not await verify_turnstile(body.turnstile_token, ip):
        raise CaptchaFailed()

    # Generic response — no user enumeration
    user = await db.get_user_by_email(body.email)
    if user and not user.get("banned"):
        reset_token = create_password_reset_token(user["uid"])
        token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
        await db.store_token(
            token_type=PASSWORD_RESET_TOKEN_TYPE,
            uid=user["uid"],
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=s.password_reset_ttl_minutes),
        )
        await send_password_reset_email(user["email"], user["username"], reset_token)
        await write_audit(
            action="user.forgot_password",
            actor=user["uid"],
            ip=ip,
        )

    return {"ok": True, "message": "If an account with that email exists, a reset link has been sent."}


# ---------------------------------------------------------------------------
# POST /auth/reset-password
# ---------------------------------------------------------------------------
@router.post("/reset-password")
async def reset_password(request: Request, body: ResetPasswordRequest):
    db = request.state.db
    ip = _get_ip(request)

    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    # Decode JWT to get uid (also validates expiry)
    try:
        token_payload = decode_token(body.token, PASSWORD_RESET_TOKEN_TYPE)
    except Exception:
        raise InvalidSession()

    uid = token_payload["sub"]
    stored = await db.consume_token(PASSWORD_RESET_TOKEN_TYPE, token_hash)
    if not stored:
        raise InvalidSession()

    new_hash = hash_password(body.new_password)
    # Increment token_version to invalidate all sessions
    user = await db.get_user_by_uid(uid)
    current_version = user.get("token_version", 1) if user else 1
    await db.update_user(uid, {
        "password_hash": new_hash,
        "token_version": current_version + 1,
    })
    await db.revoke_all_web_sessions(uid)

    await write_audit(action="user.password_reset", actor=uid, target=uid, ip=ip)

    return {"ok": True, "message": "Password reset successfully. Please log in again."}


# ---------------------------------------------------------------------------
# POST /auth/verify-email
# ---------------------------------------------------------------------------
@router.post("/verify-email")
async def verify_email(request: Request, body: VerifyEmailRequest):
    db = request.state.db
    ip = _get_ip(request)

    try:
        token_payload = decode_token(body.token, EMAIL_VERIFY_TOKEN_TYPE)
    except Exception:
        raise InvalidSession()

    uid = token_payload["sub"]
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    stored = await db.consume_token(EMAIL_VERIFY_TOKEN_TYPE, token_hash)
    if not stored:
        raise InvalidSession()

    await db.update_user(uid, {"email_verified": True})
    await write_audit(action="user.email_verified", actor=uid, target=uid, ip=ip)

    return {"ok": True, "message": "Email verified successfully."}


# ---------------------------------------------------------------------------
# POST /auth/resend-verification
# ---------------------------------------------------------------------------
@router.post("/resend-verification")
@limiter.limit("3/minute")
async def resend_verification(
    request: Request,
    payload: Dict[str, Any] = Depends(get_current_user_payload),
):
    s = get_settings()
    uid = payload["sub"]
    db = request.state.db
    ip = _get_ip(request)

    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")
    if user.get("email_verified"):
        return {"ok": True, "message": "Email is already verified."}

    verify_token = create_email_verify_token(uid, user["email"])
    token_hash = hashlib.sha256(verify_token.encode()).hexdigest()
    await db.store_token(
        token_type=EMAIL_VERIFY_TOKEN_TYPE,
        uid=uid,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=s.email_verify_ttl_hours),
        extra={"email": user["email"]},
    )
    await send_verification_email(user["email"], user["username"], verify_token)
    return {"ok": True, "message": "Verification email resent."}


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------
@router.get("/me")
async def get_me(
    request: Request,
    payload: Dict[str, Any] = Depends(get_current_user_payload),
):
    uid = payload["sub"]
    db = request.state.db
    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")

    # Validate token_version
    stored_version = user.get("token_version", 1)
    if payload.get("ver", 1) != stored_version:
        raise InvalidSession()

    return _build_user_response(user).model_dump()


# ---------------------------------------------------------------------------
# GET /auth/sessions
# ---------------------------------------------------------------------------
@router.get("/sessions")
async def get_sessions(
    request: Request,
    payload: Dict[str, Any] = Depends(get_current_user_payload),
):
    uid = payload["sub"]
    db = request.state.db
    sessions = await db.list_web_sessions(uid)
    return {"ok": True, "sessions": sessions}


# ---------------------------------------------------------------------------
# POST /auth/change-password
# ---------------------------------------------------------------------------
@router.post("/change-password")
async def change_password(
    request: Request,
    body: ChangePasswordRequest,
    response: Response,
    payload: Dict[str, Any] = Depends(get_current_user_payload),
):
    uid = payload["sub"]
    db = request.state.db
    ip = _get_ip(request)

    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")
    if not verify_password(body.current_password, user.get("password_hash", "")):
        raise InvalidCredentials()

    new_hash = hash_password(body.new_password)
    current_version = user.get("token_version", 1)
    await db.update_user(uid, {
        "password_hash": new_hash,
        "token_version": current_version + 1,
    })
    await db.revoke_all_web_sessions(uid)

    await write_audit(action="user.change_password", actor=uid, target=uid, ip=ip)

    clear_auth_cookies(response)
    return {"ok": True, "message": "Password changed. Please log in again."}


# ---------------------------------------------------------------------------
# POST /auth/change-email
# ---------------------------------------------------------------------------
@router.post("/change-email")
async def change_email(
    request: Request,
    body: ChangeEmailRequest,
    payload: Dict[str, Any] = Depends(get_current_user_payload),
):
    s = get_settings()
    uid = payload["sub"]
    db = request.state.db
    ip = _get_ip(request)

    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")
    if not verify_password(body.current_password, user.get("password_hash", "")):
        raise InvalidCredentials()

    new_email = body.new_email.lower().strip()
    existing = await db.get_user_by_email(new_email)
    if existing and existing["uid"] != uid:
        from app.core.errors import EmailTaken
        raise EmailTaken()

    # Mark unverified, send new verification
    await db.update_user(uid, {"email": new_email, "email_verified": False})
    verify_token = create_email_verify_token(uid, new_email)
    token_hash = hashlib.sha256(verify_token.encode()).hexdigest()
    await db.store_token(
        token_type=EMAIL_VERIFY_TOKEN_TYPE,
        uid=uid,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=s.email_verify_ttl_hours),
        extra={"email": new_email},
    )
    await send_verification_email(new_email, user["username"], verify_token)
    await write_audit(
        action="user.change_email",
        actor=uid,
        target=uid,
        ip=ip,
        meta={"new_email": new_email},
    )

    return {"ok": True, "message": "Email updated. Please verify your new email address."}


# ---------------------------------------------------------------------------
# POST /auth/totp/setup
# ---------------------------------------------------------------------------
@router.post("/totp/setup")
async def totp_setup(
    request: Request,
    payload: Dict[str, Any] = Depends(get_current_user_payload),
):
    uid = payload["sub"]
    db = request.state.db
    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")

    # Generate TOTP secret
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user["email"], issuer_name="Pruvate")

    # Generate QR code as data URL
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    qr_data_url = f"data:image/png;base64,{qr_b64}"

    # Encrypt secret and store temporarily (not yet enabled)
    from app.core.crypto import encrypt_license_key
    encrypted_secret = encrypt_license_key(secret)
    await db.update_user(uid, {"totp_secret_enc": encrypted_secret, "totp_enabled": False})

    return {
        "ok": True,
        "secret": secret,
        "qr_data_url": qr_data_url,
        "backup_codes": [],  # NICE: implement backup codes
    }


# ---------------------------------------------------------------------------
# POST /auth/totp/enable
# ---------------------------------------------------------------------------
@router.post("/totp/enable")
async def totp_enable(
    request: Request,
    body: TotpEnableRequest,
    payload: Dict[str, Any] = Depends(get_current_user_payload),
):
    uid = payload["sub"]
    db = request.state.db
    ip = _get_ip(request)

    user = await db.get_user_by_uid(uid)
    if not user or not user.get("totp_secret_enc"):
        raise NotFound("TOTP setup not started")

    from app.core.crypto import decrypt_license_key
    try:
        totp_secret = decrypt_license_key(user["totp_secret_enc"])
    except Exception:
        raise InternalError()

    totp = pyotp.TOTP(totp_secret)
    if not totp.verify(body.totp_code, valid_window=1):
        raise TotpInvalid()

    await db.update_user(uid, {"totp_enabled": True})
    await write_audit(action="user.totp_enabled", actor=uid, target=uid, ip=ip)

    return {"ok": True, "message": "Two-factor authentication enabled."}


# ---------------------------------------------------------------------------
# POST /auth/totp/disable
# ---------------------------------------------------------------------------
@router.post("/totp/disable")
async def totp_disable(
    request: Request,
    body: TotpDisableRequest,
    payload: Dict[str, Any] = Depends(get_current_user_payload),
):
    uid = payload["sub"]
    db = request.state.db
    ip = _get_ip(request)

    user = await db.get_user_by_uid(uid)
    if not user:
        raise NotFound("User")
    if not verify_password(body.current_password, user.get("password_hash", "")):
        raise InvalidCredentials()

    from app.core.crypto import decrypt_license_key
    try:
        totp_secret = decrypt_license_key(user["totp_secret_enc"])
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(body.totp_code, valid_window=1):
            raise TotpInvalid()
    except TotpInvalid:
        raise
    except Exception:
        raise InternalError()

    await db.update_user(uid, {"totp_enabled": False, "totp_secret_enc": None})
    await write_audit(action="user.totp_disabled", actor=uid, target=uid, ip=ip)

    return {"ok": True, "message": "Two-factor authentication disabled."}
