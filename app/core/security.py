"""
Security helpers: password hashing (argon2id + pepper), JWT tokens,
refresh token management, CSRF, and dependency utilities.
"""
import secrets
import hashlib
import hmac
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Dict, Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from fastapi import Request, Cookie, Header, Depends, HTTPException
from fastapi.responses import JSONResponse, Response
import structlog

from app.core.config import get_settings
from app.core.errors import InvalidSession, InvalidCredentials, Forbidden

log = structlog.get_logger()

_settings = None

def _s():
    global _settings
    if _settings is None:
        _settings = get_settings()
    return _settings


# ---------------------------------------------------------------------------
# Password hashing (Argon2id + server-side pepper)
# ---------------------------------------------------------------------------

def _hasher() -> PasswordHasher:
    s = _s()
    return PasswordHasher(
        time_cost=s.argon2_time_cost,
        memory_cost=s.argon2_memory_cost,
        parallelism=s.argon2_parallelism,
        hash_len=32,
        salt_len=16,
    )


def _apply_pepper(password: str) -> str:
    """HMAC-SHA256 the password with the server pepper before Argon2."""
    pepper = _s().argon2_pepper_bytes
    peppered = hmac.new(pepper, password.encode("utf-8"), hashlib.sha256).digest()
    # Return as hex string so Argon2 sees a consistent-length ASCII input
    return peppered.hex()


def hash_password(password: str) -> str:
    """Hash a password with Argon2id + pepper. Returns the hash string."""
    peppered = _apply_pepper(password)
    return _hasher().hash(peppered)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against an Argon2id hash.
    Returns True if valid, False otherwise. Always constant-time.
    """
    peppered = _apply_pepper(password)
    try:
        return _hasher().verify(password_hash, peppered)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher().check_needs_rehash(password_hash)


# ---------------------------------------------------------------------------
# HMAC-SHA256 helpers (for lookup keys, nonce MACs, etc.)
# ---------------------------------------------------------------------------

def hmac_sha256(key: bytes, data: str) -> str:
    """Returns lowercase hex HMAC-SHA256."""
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------------------
# JWT Access Tokens
# ---------------------------------------------------------------------------

ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"
EMAIL_VERIFY_TOKEN_TYPE = "email_verify"
PASSWORD_RESET_TOKEN_TYPE = "password_reset"


def _create_token(payload: Dict[str, Any], ttl_seconds: int) -> str:
    s = _s()
    now = datetime.now(timezone.utc)
    payload = {
        **payload,
        "iat": now,
        "exp": now + timedelta(seconds=ttl_seconds),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm)


def create_access_token(uid: str, token_version: int) -> str:
    s = _s()
    return _create_token(
        {"sub": uid, "type": ACCESS_TOKEN_TYPE, "ver": token_version},
        ttl_seconds=s.access_token_ttl_minutes * 60,
    )


def create_refresh_token() -> Tuple[str, str]:
    """Returns (raw_token, hashed_token). Store only the hash."""
    raw = secrets.token_hex(32)  # 256 bits
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def create_email_verify_token(uid: str, email: str) -> str:
    s = _s()
    return _create_token(
        {"sub": uid, "type": EMAIL_VERIFY_TOKEN_TYPE, "email": email},
        ttl_seconds=s.email_verify_ttl_hours * 3600,
    )


def create_password_reset_token(uid: str) -> str:
    s = _s()
    return _create_token(
        {"sub": uid, "type": PASSWORD_RESET_TOKEN_TYPE},
        ttl_seconds=s.password_reset_ttl_minutes * 60,
    )


def decode_token(token: str, expected_type: str) -> Dict[str, Any]:
    """
    Decode and validate a JWT. Raises InvalidSession on any failure.
    """
    s = _s()
    try:
        payload = jwt.decode(
            token,
            s.jwt_secret,
            algorithms=[s.jwt_algorithm],
            options={"require": ["sub", "exp", "iat", "jti", "type"]},
        )
    except jwt.ExpiredSignatureError:
        raise InvalidSession()
    except jwt.InvalidTokenError:
        raise InvalidSession()

    if payload.get("type") != expected_type:
        raise InvalidSession()

    return payload


# ---------------------------------------------------------------------------
# CSRF Token
# ---------------------------------------------------------------------------

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "x-csrf-token"


def generate_csrf_token() -> str:
    return secrets.token_hex(32)


def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    csrf_token: str,
) -> None:
    """Set all auth cookies on the response."""
    s = _s()
    is_prod = s.is_production
    access_ttl = s.access_token_ttl_minutes * 60
    refresh_ttl = s.refresh_token_ttl_days * 86400

    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=access_ttl,
        httponly=True,
        secure=is_prod,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=refresh_ttl,
        httponly=True,
        secure=is_prod,
        samesite="strict",
        path="/api/v1/auth/refresh",
    )
    # CSRF token is readable by JS (not httpOnly) so the frontend can send it as a header
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=refresh_ttl,
        httponly=False,
        secure=is_prod,
        samesite="strict",
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/api/v1/auth/refresh")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")


# ---------------------------------------------------------------------------
# FastAPI Dependencies
# ---------------------------------------------------------------------------

async def get_current_user_payload(
    request: Request,
    access_token: Optional[str] = Cookie(default=None),
) -> Dict[str, Any]:
    """
    Dependency: validates access_token cookie and CSRF header on mutating requests.
    Returns the JWT payload dict.
    """
    if not access_token:
        raise InvalidSession()

    # CSRF check for state-mutating methods
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME, "")
        csrf_header = request.headers.get(CSRF_HEADER_NAME, "")
        if not csrf_cookie or not constant_time_compare(csrf_cookie, csrf_header):
            raise Forbidden()

    return decode_token(access_token, ACCESS_TOKEN_TYPE)


async def get_current_uid(payload: Dict[str, Any] = Depends(get_current_user_payload)) -> str:
    """Dependency: returns the current user's UID."""
    return payload["sub"]


async def get_loader_session_token(request: Request) -> str:
    """Dependency: extracts loader session token from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise InvalidSession()
    token = auth[7:].strip()
    if not token:
        raise InvalidSession()
    return token


def hash_refresh_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_loader_session_token() -> str:
    """256-bit opaque session token for loader sessions."""
    return secrets.token_hex(32)


def hash_loader_session_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()
