"""
Pydantic v2 schemas for all request bodies and responses.
"""
from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field, field_validator, EmailStr, model_validator
import re

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')


class OkResponse(BaseModel):
    ok: bool = True


# ---------------------------------------------------------------------------
# AUTH
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    email: EmailStr
    password: str = Field(..., min_length=10, max_length=128)
    turnstile_token: str = Field(default="")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not USERNAME_RE.match(v):
            raise ValueError("Username must be 3-20 characters: letters, numbers, underscores only.")
        return v

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("Password must be at least 10 characters.")
        checks = [
            any(c.isupper() for c in v),
            any(c.islower() for c in v),
            any(c.isdigit() for c in v),
        ]
        if sum(checks) < 2:
            raise ValueError("Password must contain at least uppercase, lowercase, and a digit.")
        return v


class LoginRequest(BaseModel):
    identifier: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)
    totp_code: Optional[str] = Field(default=None, min_length=6, max_length=8)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    turnstile_token: str = Field(default="")


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=10, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("Password must be at least 10 characters.")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=10, max_length=128)


class ChangeEmailRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_email: EmailStr


class VerifyEmailRequest(BaseModel):
    token: str


class TotpSetupResponse(BaseModel):
    ok: bool = True
    secret: str
    qr_data_url: str
    backup_codes: List[str]


class TotpEnableRequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=8)


class TotpDisableRequest(BaseModel):
    current_password: str
    totp_code: str = Field(..., min_length=6, max_length=8)


# ---------------------------------------------------------------------------
# USER / SUBSCRIPTION RESPONSES
# ---------------------------------------------------------------------------

class HwidInfo(BaseModel):
    bound: bool
    bound_at: Optional[datetime] = None
    last_reset_at: Optional[datetime] = None


class SubscriptionInfo(BaseModel):
    status: str
    expires_at: Optional[datetime] = None
    days_left: Optional[int] = None
    lifetime: bool = False
    product_id: Optional[str] = None
    product_name: Optional[str] = None


class UserResponse(BaseModel):
    ok: bool = True
    uid: str
    username: str
    email: str
    admin: bool
    email_verified: bool
    totp_enabled: bool
    subscription: SubscriptionInfo
    subscriptions: Optional[List[Dict[str, Any]]] = None
    hwid: HwidInfo
    created_at: datetime
    last_login_at: Optional[datetime] = None


class LoginResponse(BaseModel):
    ok: bool = True
    user: UserResponse
    csrf_token: str


# ---------------------------------------------------------------------------
# LICENSE
# ---------------------------------------------------------------------------

class RedeemKeyRequest(BaseModel):
    key: str = Field(..., min_length=10, max_length=60)


class RedeemKeyResponse(BaseModel):
    ok: bool = True
    days_added: Optional[int] = None
    days_left: Optional[int] = None
    expires_at: Optional[datetime] = None
    lifetime: bool = False
    product_id: Optional[str] = None
    product_name: Optional[str] = None
    subscriptions: Optional[List[Dict[str, Any]]] = None


# ---------------------------------------------------------------------------
# HWID
# ---------------------------------------------------------------------------

class HwidResetRequest(BaseModel):
    username: str
    password: str = Field(..., min_length=1, max_length=128)


# ---------------------------------------------------------------------------
# LOADER PROTOCOL
# ---------------------------------------------------------------------------

class HwidComponents(BaseModel):
    combined_hash: str = Field(..., min_length=10, max_length=128)
    components: List[str] = Field(..., min_length=1, max_length=10)


class LoaderLoginRequest(BaseModel):
    app_id: str
    build: str
    product_id: Optional[str] = None
    identifier: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)
    hwid: HwidComponents
    client_nonce: str = Field(..., min_length=16, max_length=64)
    client_ephemeral_pub: str = Field(..., min_length=10, max_length=128)
    ts: int  # Unix timestamp from client


class LoaderHeartbeatRequest(BaseModel):
    session_token: str
    seq: int = Field(..., ge=1)
    nonce: str = Field(..., min_length=16, max_length=64)
    ts: int
    mac: str = Field(..., min_length=10, max_length=128)


class LoaderLogoutRequest(BaseModel):
    session_token: str


# ---------------------------------------------------------------------------
# SCRIPTS
# ---------------------------------------------------------------------------

class CreateScriptRequest(BaseModel):
    title: Optional[str] = Field(default=None, max_length=120)
    name: Optional[str] = Field(default=None, max_length=120)
    description: str = Field(default="", max_length=2000)
    code: str = Field(..., min_length=1, max_length=524288)
    tags: List[str] = Field(default_factory=list)
    product_id: Optional[str] = Field(default=None, max_length=64)
    cover_url: Optional[str] = Field(default=None, max_length=500)


class ScriptResponse(BaseModel):
    ok: bool = True
    id: str
    title: str
    description: str
    tags: List[str]
    author_uid: str
    status: str
    downloads: int
    likes: int
    cover_image_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ScriptListResponse(BaseModel):
    ok: bool = True
    scripts: List[ScriptResponse]
    total: int
    page: int
    limit: int


# ---------------------------------------------------------------------------
# ADMIN
# ---------------------------------------------------------------------------

class CreateProductRequest(BaseModel):
    product_id: str = Field(..., min_length=2, max_length=64, pattern=r'^[A-Za-z0-9_-]+$')
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(default="", max_length=500)


class GenerateLicensesRequest(BaseModel):
    prefix: str = Field(default="PRVT", min_length=2, max_length=12, pattern=r'^[A-Z0-9]+$')
    quantity: int = Field(default=1, ge=1, le=1000)
    duration_days: Optional[int] = Field(default=None, ge=1, le=36500)
    fixed_expires_at: Optional[datetime] = None
    lifetime: bool = False
    product_id: Optional[str] = Field(default="default", max_length=64)
    product_name: Optional[str] = Field(default=None, max_length=120)
    discord_id: Optional[str] = Field(default=None, min_length=17, max_length=20, pattern=r'^\d+$')
    note: Optional[str] = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def validate_duration(self) -> "GenerateLicensesRequest":
        if not self.lifetime and not self.duration_days and not self.fixed_expires_at:
            raise ValueError("Must specify duration_days, fixed_expires_at, or lifetime=true.")
        return self


class BanRequest(BaseModel):
    reason: str = Field(default="", max_length=500)


class AddDaysRequest(BaseModel):
    days: int = Field(..., ge=1, le=3650)
    product_id: Optional[str] = None


class AdminChangeEmailRequest(BaseModel):
    new_email: EmailStr


class AdminChangePasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=10, max_length=128)


class UpdateSettingsRequest(BaseModel):
    maintenance_mode: Optional[bool] = None
    registration_open: Optional[bool] = None
    hwid_reset_cooldown_days: Optional[int] = Field(default=None, ge=0, le=365)
    max_sessions: Optional[int] = Field(default=None, ge=1, le=10)
    loader_download_requires_subscription: Optional[bool] = None
    min_loader_version: Optional[str] = None


class CreateAnnouncementRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    body: str = Field(..., min_length=1, max_length=2000)
    type: str = Field(default="info", pattern=r'^(info|warning|danger)$')
    active: bool = True


class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    scopes: List[str] = Field(default_factory=list)
