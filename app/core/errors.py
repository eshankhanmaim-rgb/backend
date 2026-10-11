"""
Unified error handling for the Pruvate Auth Platform.
All API errors use: {"ok": false, "code": "SNAKE_CASE", "message": "Human message"}
"""
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import structlog

log = structlog.get_logger()


class AppError(Exception):
    """Base application error that maps to a JSON error response."""
    def __init__(self, code: str, message: str, status_code: int = 400):
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


# --- Specific error classes ---
class InvalidCredentials(AppError):
    def __init__(self): super().__init__("INVALID_CREDENTIALS", "Invalid username or password.", 401)

class UserBanned(AppError):
    def __init__(self, reason: str = ""): super().__init__("BANNED", f"Your account has been suspended.{' Reason: ' + reason if reason else ''}", 403)

class HwidMismatch(AppError):
    def __init__(self): super().__init__("HWID_MISMATCH", "Hardware ID mismatch. Please reset your HWID from the dashboard.", 403)

class NoSubscription(AppError):
    def __init__(self): super().__init__("NO_SUBSCRIPTION", "No active subscription found. Please redeem a license key.", 403)

class SubscriptionExpired(AppError):
    def __init__(self): super().__init__("SUBSCRIPTION_EXPIRED", "Your subscription has expired. Please redeem a new key.", 403)

class SubscriptionDisabled(AppError):
    def __init__(self): super().__init__("SUBSCRIPTION_DISABLED", "Your subscription has been disabled. Please contact support.", 403)

class UpdateRequired(AppError):
    def __init__(self): super().__init__("UPDATE_REQUIRED", "This version of the loader is no longer supported. Please download the latest version.", 426)

class MaintenanceMode(AppError):
    def __init__(self): super().__init__("MAINTENANCE", "The service is temporarily under maintenance. Please try again later.", 503)

class RateLimited(AppError):
    def __init__(self): super().__init__("RATE_LIMITED", "Too many requests. Please slow down.", 429)

class InvalidSession(AppError):
    def __init__(self): super().__init__("INVALID_SESSION", "Session is invalid, expired, or revoked.", 401)

class EmailNotVerified(AppError):
    def __init__(self): super().__init__("EMAIL_NOT_VERIFIED", "Please verify your email address before continuing.", 403)

class UsernameTaken(AppError):
    def __init__(self): super().__init__("USERNAME_TAKEN", "That username is already in use.", 409)

class EmailTaken(AppError):
    def __init__(self): super().__init__("EMAIL_TAKEN", "An account with that email already exists.", 409)

class InvalidKey(AppError):
    def __init__(self): super().__init__("INVALID_KEY", "License key not found or invalid format.", 404)

class KeyAlreadyClaimed(AppError):
    def __init__(self): super().__init__("KEY_ALREADY_CLAIMED", "This key has already been redeemed.", 409)

class KeyBanned(AppError):
    def __init__(self): super().__init__("KEY_BANNED", "This key has been banned.", 403)

class HwidCooldown(AppError):
    def __init__(self, days_left: int): super().__init__("HWID_COOLDOWN", f"HWID reset is on cooldown. Try again in {days_left} day(s).", 429)

class CaptchaFailed(AppError):
    def __init__(self): super().__init__("CAPTCHA_FAILED", "CAPTCHA verification failed. Please try again.", 400)

class TotpRequired(AppError):
    def __init__(self): super().__init__("TOTP_REQUIRED", "Two-factor authentication code required.", 401)

class TotpInvalid(AppError):
    def __init__(self): super().__init__("TOTP_INVALID", "Invalid two-factor authentication code.", 401)

class NotFound(AppError):
    def __init__(self, resource: str = "Resource"): super().__init__("NOT_FOUND", f"{resource} not found.", 404)

class Forbidden(AppError):
    def __init__(self): super().__init__("FORBIDDEN", "You do not have permission to perform this action.", 403)

class InternalError(AppError):
    def __init__(self): super().__init__("INTERNAL_ERROR", "An internal error occurred. Please try again later.", 500)


# --- FastAPI exception handlers ---
def _err(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse(status_code=status, content={"ok": False, "code": code, "message": message})


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    if exc.status_code >= 500:
        log.error("app_error", code=exc.code, path=str(request.url), status=exc.status_code)
    return _err(exc.code, exc.message, exc.status_code)


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Summarize validation errors without leaking internals
    field_errors = []
    for err in exc.errors():
        loc = " -> ".join(str(l) for l in err["loc"] if l != "body")
        field_errors.append(f"{loc}: {err['msg']}" if loc else err["msg"])
    message = "; ".join(field_errors[:5])  # cap at 5
    return _err("VALIDATION_ERROR", message, 422)


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code_map = {
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        429: "RATE_LIMITED",
        500: "INTERNAL_ERROR",
        503: "SERVICE_UNAVAILABLE",
    }
    code = code_map.get(exc.status_code, "HTTP_ERROR")
    return _err(code, str(exc.detail), exc.status_code)


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled_exception", exc_type=type(exc).__name__, path=str(request.url), exc_info=exc)
    return _err("INTERNAL_ERROR", "An internal error occurred. Please try again later.", 500)
