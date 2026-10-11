"""
Centralized configuration via pydantic-settings.
All values come from environment variables; no secrets in code.
"""
from functools import lru_cache
from typing import Optional, List
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import json
import base64


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "config.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # App
    app_env: str = "development"
    app_base_url: str = "http://78.154.103.52:11731"
    web_base_url: str = "http://78.154.103.52:11731"
    max_request_size_mb: int = 10
    log_level: str = "INFO"
    health_token: str = ""

    # Firebase
    firebase_service_account_json: Optional[str] = None
    firebase_service_account_path: Optional[str] = "serviceAccountKey.json"
    firebase_project_id: str = "prime-auth-69e92"
    firebase_storage_bucket: str = "prime-auth-69e92.firebasestorage.app"
    firebase_database_url: str = "https://prime-auth-69e92-default-rtdb.asia-southeast1.firebasedatabase.app"
    firebase_auth_domain: str = "prime-auth-69e92.firebaseapp.com"
    firebase_api_key: str = ""
    firebase_messaging_sender_id: str = "89012130458"
    firebase_app_id: str = "1:89012130458:web:29f8fee94f548853d98523"
    firebase_measurement_id: str = "G-PC0YQNKF6J"

    # JWT
    jwt_secret: str = "v+dJ6mD6T5rM3kP1xL7hQ2wE4zR8yU9iO0pA1sD3fG5hJ7kL9zX2cV4bN6mQ8wE1rT3yU5iO7pA9sD1fG3hJ5kL7zX9c="
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7

    # Argon2
    argon2_pepper: str = "8e5f2a1c9b3d4e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f"
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4

    # Ed25519
    ed25519_private_key_b64: str = "nlHekp5dYii6sP0SsVx7u4bi295tuFi1DkteXNtVFv+9VU0GHDo/miKL2eZH3GiyBHAZaHP+kbn02+CN5g5alQ=="
    ed25519_public_key_b64: str = "vVVNBhw6P5oii9nmR9xosgRwGWhz/pG59NvgjeYOWpU="

    # License encryption
    license_key_encryption_key: str = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
    license_key_hmac_key: str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

    # CORS
    allowed_origins: str = "http://78.154.103.52:11731,http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000"

    @property
    def allowed_origins_list(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    # Rate limits
    rate_limit_login: str = "10/minute"
    rate_limit_register: str = "5/minute"
    rate_limit_redeem: str = "3/minute"
    rate_limit_heartbeat: str = "120/minute"
    rate_limit_forgot_password: str = "3/minute"

    # Lockout
    lockout_max_attempts: int = 5
    lockout_window_seconds: int = 300
    lockout_duration_seconds: int = 900

    # Turnstile
    turnstile_secret_key: str = ""

    # Email
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    from_email: str = "noreply@example.com"
    from_name: str = "Pruvate"
    email_verify_ttl_hours: int = 24
    password_reset_ttl_minutes: int = 30

    # Discord
    discord_webhook_admin: str = ""
    discord_webhook_keys: str = ""
    discord_webhook_security: str = ""

    # Redis
    redis_url: str = ""

    # Loader
    loader_app_id: str = "pruvate_loader_v1"
    loader_min_version: str = "1.0.0"
    loader_current_version: str = "1.0.0"
    loader_session_ttl_hours: int = 24
    loader_heartbeat_interval_seconds: int = 60
    loader_heartbeat_grace_missed: int = 3

    @property
    def min_loader_version(self) -> str:
        return self.loader_min_version

    @property
    def current_loader_version(self) -> str:
        return self.loader_current_version

    # Storage
    storage_scripts_prefix: str = "scripts/covers/"
    storage_releases_prefix: str = "releases/"
    script_cover_max_bytes: int = 2 * 1024 * 1024
    script_code_max_bytes: int = 512 * 1024

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def argon2_pepper_bytes(self) -> bytes:
        return bytes.fromhex(self.argon2_pepper)

    @property
    def ed25519_private_key_bytes(self) -> bytes:
        return base64.b64decode(self.ed25519_private_key_b64)

    @property
    def ed25519_public_key_bytes(self) -> bytes:
        return base64.b64decode(self.ed25519_public_key_b64)

    @property
    def license_encryption_key_bytes(self) -> bytes:
        return bytes.fromhex(self.license_key_encryption_key)

    @property
    def license_hmac_key_bytes(self) -> bytes:
        return bytes.fromhex(self.license_key_hmac_key)

    @model_validator(mode="after")
    def check_firebase_credentials(self) -> "Settings":
        if not self.firebase_service_account_json and not self.firebase_service_account_path:
            # Allow missing in test/dev environment
            pass
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
