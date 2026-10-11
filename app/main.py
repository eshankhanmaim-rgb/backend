"""
FastAPI application factory.
Sets up middleware, exception handlers, routers, static SPA serving, and the database adapter.
"""
import json
import os
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Callable

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.core.config import get_settings
from app.core.errors import (
    AppError,
    app_error_handler,
    validation_error_handler,
    http_exception_handler,
    generic_exception_handler,
)
from app.core.rate_limit import limiter, slowapi_error_handler
from app.core.audit import set_db_adapter
from app.routers import auth, health, client, admin, loader

BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------
def init_firebase_adapter():
    """Initialize Firebase Admin SDK for project prime-auth-69e92 and return the active DatabaseAdapter."""
    import firebase_admin
    from firebase_admin import credentials, firestore

    s = get_settings()

    if not firebase_admin._apps:
        sa_path = s.firebase_service_account_path
        resolved_sa_path = None
        if sa_path:
            if os.path.exists(sa_path):
                resolved_sa_path = sa_path
            elif (BASE_DIR / sa_path).exists():
                resolved_sa_path = str(BASE_DIR / sa_path)

        if s.firebase_service_account_json:
            cred_dict = json.loads(s.firebase_service_account_json)
            cred = credentials.Certificate(cred_dict)
        elif resolved_sa_path:
            cred = credentials.Certificate(resolved_sa_path)
        elif (BASE_DIR / "serviceAccountKey.json").exists():
            cred = credentials.Certificate(str(BASE_DIR / "serviceAccountKey.json"))
        else:
            cred = credentials.ApplicationDefault()

        options = {
            "projectId": s.firebase_project_id,
            "storageBucket": s.firebase_storage_bucket,
        }
        if s.firebase_database_url:
            options["databaseURL"] = s.firebase_database_url

        firebase_admin.initialize_app(cred, options)

    if s.firebase_database_url:
        from app.adapters.rtdb import RealtimeDatabaseAdapter
        return RealtimeDatabaseAdapter()

    from app.adapters.firestore import FirestoreAdapter
    return FirestoreAdapter(firestore.client())


# ---------------------------------------------------------------------------
# Request ID + logging middleware
# ---------------------------------------------------------------------------
import uuid as _uuid

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        request_id = str(_uuid.uuid4())
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)
        s = get_settings()
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if s.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        if request.url.path.startswith("/api/") or request.url.path == "/health":
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; "
                "frame-ancestors 'none'; "
                "base-uri 'none';"
            )
        return response


# ---------------------------------------------------------------------------
# DB injection middleware
# ---------------------------------------------------------------------------
class DBMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, db_adapter):
        super().__init__(app)
        self._db = db_adapter

    async def dispatch(self, request: Request, call_next: Callable):
        request.state.db = self._db
        return await call_next(request)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
_db_adapter = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db_adapter
    log = structlog.get_logger()

    # Initialize Firebase + adapter
    try:
        _db_adapter = init_firebase_adapter()
        set_db_adapter(_db_adapter)
        log.info("firebase_initialized", adapter=type(_db_adapter).__name__)
    except Exception as e:
        log.error("firebase_init_failed", error=str(e))
        _db_adapter = None

    yield

    log.info("shutdown")


def create_app() -> FastAPI:
    s = get_settings()

    app = FastAPI(
        title="Pruvate Auth API",
        version="1.0.0",
        docs_url="/docs" if not s.is_production else None,
        redoc_url="/redoc" if not s.is_production else None,
        openapi_url="/openapi.json" if not s.is_production else None,
        lifespan=lifespan,
    )

    # Rate limiter
    app.state.limiter = limiter

    # Middleware (order matters: outermost = first to process request)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=s.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID", "Authorization", "X-App-Id"],
        expose_headers=["X-Request-ID", "X-Signature"],
    )
    app.add_middleware(SlowAPIMiddleware)

    # Exception handlers
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RateLimitExceeded, slowapi_error_handler)
    app.add_exception_handler(Exception, generic_exception_handler)

    # DB middleware — inject adapter into request.state.db
    @app.middleware("http")
    async def inject_db(request: Request, call_next: Callable):
        from app.core import audit
        adapter = getattr(request.app.state, "db", None) or _db_adapter or audit._db_adapter
        request.state.db = adapter
        return await call_next(request)

    # Routers
    app.include_router(health.router)
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(client.router, prefix="/api/v1")
    app.include_router(loader.router, prefix="/api/v1")
    app.include_router(admin.router, prefix="/api/v1/admin")

    # Optional bundled frontend SPA serving if static/index.html is present
    static_dir = BASE_DIR / "static"
    if (static_dir / "index.html").exists():
        if (static_dir / "assets").exists():
            app.mount("/assets", StaticFiles(directory=str(static_dir / "assets")), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(full_path: str):
            candidate = static_dir / full_path
            if full_path and candidate.is_file():
                return FileResponse(str(candidate))
            return FileResponse(str(static_dir / "index.html"))
    else:
        @app.get("/", include_in_schema=False)
        async def root_index():
            return {
                "status": "online",
                "service": "Pruvate Auth API",
                "version": "1.0.0",
                "docs": "/docs",
                "health": "/health",
            }

    return app


app = create_app()
