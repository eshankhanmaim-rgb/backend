"""
Rate limiting using slowapi + per-account progressive lockout.
"""
from typing import Callable, Optional
from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import structlog

from app.core.errors import RateLimited as RateLimitedError

log = structlog.get_logger()


def _get_real_ip(request: Request) -> str:
    """
    Extract real IP, respecting X-Forwarded-For from trusted proxies.
    Never trust the header blindly in production; this assumes a correctly
    configured reverse proxy that strips/sets this header.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return get_remote_address(request)


# Global limiter — keyed by IP by default
limiter = Limiter(
    key_func=_get_real_ip,
    default_limits=[],  # no global default; set per endpoint
    headers_enabled=True,
    strategy="fixed-window",
)


async def slowapi_error_handler(request: Request, exc: RateLimitExceeded):
    """Convert slowapi's exception to our unified error format."""
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=429,
        content={"ok": False, "code": "RATE_LIMITED", "message": "Too many requests. Please slow down."},
        headers={"Retry-After": str(exc.retry_after) if hasattr(exc, 'retry_after') else "60"},
    )


# ---------------------------------------------------------------------------
# In-memory progressive lockout (use Redis for multi-instance deployments)
# ---------------------------------------------------------------------------
from collections import defaultdict
from datetime import datetime, timezone
import asyncio

_lockouts: dict = defaultdict(lambda: {"attempts": 0, "locked_until": None, "last_attempt": None})
_lockout_lock = asyncio.Lock()


async def check_lockout(identifier: str) -> None:
    """
    Check if an identifier (username or IP) is locked out.
    Raises RateLimitedError if locked.
    """
    from app.core.config import get_settings
    s = get_settings()
    async with _lockout_lock:
        entry = _lockouts[identifier]
        now = datetime.now(timezone.utc).timestamp()
        if entry["locked_until"] and now < entry["locked_until"]:
            raise RateLimitedError()


async def record_failed_attempt(identifier: str) -> None:
    """Record a failed login attempt. Locks if threshold exceeded."""
    from app.core.config import get_settings
    s = get_settings()
    async with _lockout_lock:
        entry = _lockouts[identifier]
        now = datetime.now(timezone.utc).timestamp()

        # Reset counter if outside the window
        if entry["last_attempt"] and (now - entry["last_attempt"]) > s.lockout_window_seconds:
            entry["attempts"] = 0
            entry["locked_until"] = None

        entry["attempts"] += 1
        entry["last_attempt"] = now

        if entry["attempts"] >= s.lockout_max_attempts:
            entry["locked_until"] = now + s.lockout_duration_seconds
            log.warning("account_locked", identifier=identifier, attempts=entry["attempts"])


async def clear_failed_attempts(identifier: str) -> None:
    """Clear lockout state on successful auth."""
    async with _lockout_lock:
        _lockouts[identifier] = {"attempts": 0, "locked_until": None, "last_attempt": None}


# ---------------------------------------------------------------------------
# Cloudflare Turnstile CAPTCHA verification
# ---------------------------------------------------------------------------

async def verify_turnstile(token: str, remote_ip: str) -> bool:
    """Verify a Cloudflare Turnstile token. Returns True if valid."""
    from app.core.config import get_settings
    import httpx
    s = get_settings()
    secret = s.turnstile_secret_key
    if not secret:
        return True  # CAPTCHA disabled in development
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={"secret": secret, "response": token, "remoteip": remote_ip},
            )
            data = resp.json()
            return data.get("success", False)
    except Exception:
        return False
