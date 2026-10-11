"""
pytest fixtures and test configuration.
Full in-memory DatabaseAdapter for tests — zero Firebase dependency.
"""
import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator, Dict, Any, Optional, List, Tuple

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from fastapi import Request

from app.adapters.base import DatabaseAdapter
from app.core.security import hash_password, create_access_token, generate_csrf_token
from app.core.audit import set_db_adapter


# ---------------------------------------------------------------------------
# In-memory DatabaseAdapter (no Firebase)
# ---------------------------------------------------------------------------

class InMemoryAdapter(DatabaseAdapter):
    """Fully in-memory adapter for testing."""

    def __init__(self):
        self.users: Dict[str, Dict] = {}
        self.usernames: Dict[str, str] = {}
        self.emails: Dict[str, str] = {}
        self.web_sessions: Dict[str, Dict] = {}
        self.auth_tokens: Dict[str, Dict] = {}
        self.nonces: Dict[str, float] = {}
        self.licenses: Dict[str, Dict] = {}
        self.loader_sessions: Dict[str, Dict] = {}
        self.scripts: Dict[str, Dict] = {}
        self.releases: Dict[str, Dict] = {}
        self.api_keys: Dict[str, Dict] = {}
        self.audit_logs: List[Dict] = []
        self.announcements: Dict[str, Dict] = {}
        self._settings: Dict = {
            "maintenance_mode": False,
            "registration_open": True,
            "hwid_reset_cooldown_days": 7,
            "max_sessions": 1,
            "loader_download_requires_subscription": False,
            "min_loader_version": "1.0.0",
            "current_loader_version": "1.0.0",
        }
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # USERS
    # ------------------------------------------------------------------
    async def get_user_by_uid(self, uid: str) -> Optional[Dict]:
        u = self.users.get(uid)
        return dict(u) if u else None

    async def get_user_by_username(self, username: str) -> Optional[Dict]:
        uid = self.usernames.get(username.lower())
        if not uid:
            return None
        u = self.users.get(uid)
        return dict(u) if u else None

    async def get_user_by_email(self, email: str) -> Optional[Dict]:
        uid = self.emails.get(email.lower().strip())
        if not uid:
            return None
        u = self.users.get(uid)
        return dict(u) if u else None

    async def get_user_by_identifier(self, identifier: str) -> Optional[Dict]:
        user = await self.get_user_by_username(identifier)
        if user:
            return user
        if "@" in identifier:
            return await self.get_user_by_email(identifier)
        return None

    async def create_user(self, uid: str, username: str, email: str, password_hash: str) -> Dict:
        async with self._lock:
            from app.core.errors import UsernameTaken, EmailTaken
            if username.lower() in self.usernames:
                raise UsernameTaken()
            if email.lower() in self.emails:
                raise EmailTaken()
            now = datetime.now(timezone.utc)
            user: Dict[str, Any] = {
                "uid": uid, "username": username, "email": email.lower(),
                "password_hash": password_hash, "admin": False, "banned": False,
                "ban_reason": None, "email_verified": False,
                "hwid": {
                    "combined_hash": None, "components": [],
                    "bound_at": None, "last_reset_at": None,
                },
                "subscription": {"status": "none", "expires_at": None},
                "totp_secret_enc": None, "totp_enabled": False,
                "token_version": 1, "created_at": now,
                "last_login_at": None, "last_login_ip": None,
            }
            self.users[uid] = user
            self.usernames[username.lower()] = uid
            self.emails[email.lower()] = uid
            return dict(user)

    async def update_user(self, uid: str, updates: Dict) -> None:
        if uid not in self.users:
            return

        def _deep_update(base: dict, upd: dict) -> None:
            for k, v in upd.items():
                if k == "subscriptions" or (isinstance(v, dict) and not v):
                    base[k] = dict(v)
                elif isinstance(v, dict) and isinstance(base.get(k), dict):
                    _deep_update(base[k], v)
                else:
                    base[k] = v

        _deep_update(self.users[uid], updates)

    async def list_users(self, search: Optional[str] = None, page: int = 1, limit: int = 50) -> Tuple[List[Dict], int]:
        users = [dict(u) for u in self.users.values()]
        if search:
            s = search.lower()
            users = [u for u in users if s in u.get("username", "").lower() or s in u.get("email", "").lower()]
        total = len(users)
        return users[(page - 1) * limit: page * limit], total

    # ------------------------------------------------------------------
    # WEB SESSIONS
    # ------------------------------------------------------------------
    async def create_web_session(self, uid: str, token_hash: str, ip: str, user_agent: str, family_id: str) -> str:
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        self.web_sessions[session_id] = {
            "uid": uid, "token_hash": token_hash, "family_id": family_id,
            "ip": ip, "user_agent": user_agent, "created_at": now,
            "last_used_at": now, "expires_at": now + timedelta(days=7),
            "revoked": False, "session_id": session_id,
        }
        return session_id

    async def get_web_session_by_token_hash(self, token_hash: str) -> Optional[Dict]:
        for sid, sess in self.web_sessions.items():
            if sess["token_hash"] == token_hash and not sess["revoked"]:
                return dict(sess)
        return None

    async def rotate_web_session(self, session_id: str, new_token_hash: str, ip: str) -> None:
        if session_id in self.web_sessions:
            self.web_sessions[session_id]["token_hash"] = new_token_hash
            self.web_sessions[session_id]["last_used_at"] = datetime.now(timezone.utc)
            self.web_sessions[session_id]["ip"] = ip

    async def revoke_web_session(self, session_id: str) -> None:
        if session_id in self.web_sessions:
            self.web_sessions[session_id]["revoked"] = True

    async def revoke_all_web_sessions(self, uid: str) -> None:
        for sess in self.web_sessions.values():
            if sess["uid"] == uid:
                sess["revoked"] = True

    async def detect_refresh_token_reuse(self, family_id: str, token_hash: str) -> bool:
        for sess in self.web_sessions.values():
            if (sess["family_id"] == family_id
                    and sess["revoked"]
                    and sess["token_hash"] != token_hash):
                return True
        return False

    async def list_web_sessions(self, uid: str) -> List[Dict]:
        return [
            {k: v for k, v in s.items() if k != "token_hash"}
            for s in self.web_sessions.values()
            if s["uid"] == uid and not s["revoked"]
        ]

    # ------------------------------------------------------------------
    # AUTH TOKENS (email verify, password reset)
    # ------------------------------------------------------------------
    async def store_token(self, token_type: str, uid: str, token_hash: str,
                          expires_at: datetime, extra: Optional[Dict] = None) -> None:
        self.auth_tokens[token_hash] = {
            "type": token_type, "uid": uid, "token_hash": token_hash,
            "expires_at": expires_at, "extra": extra or {},
        }

    async def consume_token(self, token_type: str, token_hash: str) -> Optional[Dict]:
        async with self._lock:
            t = self.auth_tokens.get(token_hash)
            if not t:
                return None
            if t["type"] != token_type:
                return None
            if datetime.now(timezone.utc) > t["expires_at"]:
                del self.auth_tokens[token_hash]
                return None
            del self.auth_tokens[token_hash]
            return t

    # ------------------------------------------------------------------
    # NONCES
    # ------------------------------------------------------------------
    async def check_and_store_nonce(self, nonce: str, ttl_seconds: int) -> bool:
        async with self._lock:
            now = datetime.now(timezone.utc).timestamp()
            if nonce in self.nonces and now < self.nonces[nonce]:
                return False
            self.nonces[nonce] = now + ttl_seconds
            return True

    # ------------------------------------------------------------------
    # LICENSES
    # ------------------------------------------------------------------
    async def create_license(self, license_id: str, key_lookup: str, key_enc: str, prefix: str,
                              duration_days: Optional[int], fixed_expires_at: Optional[datetime],
                              lifetime: bool, discord_id: Optional[str], note: Optional[str],
                              batch_id: Optional[str], created_by: str,
                              product_id: Optional[str] = "default",
                              product_name: Optional[str] = "Default Product") -> Dict:
        now = datetime.now(timezone.utc)
        data: Dict[str, Any] = {
            "id": license_id, "key_lookup": key_lookup, "key_enc": key_enc,
            "prefix": prefix, "duration_days": duration_days,
            "fixed_expires_at": fixed_expires_at, "lifetime": lifetime,
            "status": "unused", "discord_id": discord_id, "note": note,
            "batch_id": batch_id, "created_by": created_by, "created_at": now,
            "product_id": product_id or "default",
            "product_name": product_name or "Default Product",
            "claimed_by": None, "claimed_at": None, "starts_at": None, "ends_at": None,
            "banned_at": None, "ban_reason": None,
        }
        self.licenses[license_id] = data
        return dict(data)

    async def get_license_by_lookup(self, key_lookup: str) -> Optional[Dict]:
        for lic in self.licenses.values():
            if lic["key_lookup"] == key_lookup:
                return dict(lic)
        return None

    async def get_license_by_id(self, license_id: str) -> Optional[Dict]:
        lic = self.licenses.get(license_id)
        return dict(lic) if lic else None

    async def claim_license_atomic(self, license_id: str, uid: str,
                                    starts_at: datetime, ends_at: Optional[datetime]) -> bool:
        async with self._lock:
            lic = self.licenses.get(license_id)
            if not lic or lic["status"] != "unused":
                return False
            lic["status"] = "claimed"
            lic["claimed_by"] = uid
            lic["claimed_at"] = datetime.now(timezone.utc)
            lic["starts_at"] = starts_at
            lic["ends_at"] = ends_at
            return True

    async def update_license(self, license_id: str, updates: Dict) -> None:
        if license_id in self.licenses:
            self.licenses[license_id].update(updates)

    async def list_licenses(self, search: Optional[str] = None, status: Optional[str] = None,
                             page: int = 1, limit: int = 50) -> Tuple[List[Dict], int]:
        licenses = [dict(lic) for lic in self.licenses.values()]
        if status:
            licenses = [l for l in licenses if l["status"] == status]
        if search:
            s = search.lower()
            licenses = [l for l in licenses if
                        s in l["id"].lower() or s in (l.get("claimed_by") or "").lower()]
        total = len(licenses)
        return licenses[(page - 1) * limit: page * limit], total

    async def get_user_active_licenses(self, uid: str) -> List[Dict]:
        return [dict(l) for l in self.licenses.values()
                if l.get("claimed_by") == uid and l["status"] == "claimed"]

    # ------------------------------------------------------------------
    # LOADER SESSIONS
    # ------------------------------------------------------------------
    async def create_loader_session(self, session_id: str, uid: str, token_hash: str,
                                     hwid_hash: str, ip: str, app_version: str,
                                     expires_at: datetime) -> None:
        now = datetime.now(timezone.utc)
        self.loader_sessions[session_id] = {
            "session_id": session_id, "uid": uid, "token_hash": token_hash,
            "hwid_hash": hwid_hash, "ip": ip, "app_version": app_version,
            "created_at": now, "last_heartbeat_at": now, "expires_at": expires_at,
            "last_seq": 0, "revoked": False,
        }

    async def get_loader_session_by_token_hash(self, token_hash: str) -> Optional[Dict]:
        for s in self.loader_sessions.values():
            if s["token_hash"] == token_hash and not s["revoked"]:
                return dict(s)
        return None

    async def update_loader_session(self, session_id: str, updates: Dict) -> None:
        if session_id in self.loader_sessions:
            self.loader_sessions[session_id].update(updates)

    async def revoke_loader_session(self, session_id: str) -> None:
        if session_id in self.loader_sessions:
            self.loader_sessions[session_id]["revoked"] = True

    async def revoke_user_loader_sessions(self, uid: str) -> None:
        for s in self.loader_sessions.values():
            if s["uid"] == uid:
                s["revoked"] = True

    async def count_active_loader_sessions(self, uid: str) -> int:
        now = datetime.now(timezone.utc)
        return sum(
            1 for s in self.loader_sessions.values()
            if s["uid"] == uid and not s["revoked"] and s["expires_at"] > now
        )

    async def get_oldest_loader_session(self, uid: str) -> Optional[Dict]:
        sessions = [s for s in self.loader_sessions.values()
                    if s["uid"] == uid and not s["revoked"]]
        if not sessions:
            return None
        return dict(min(sessions, key=lambda s: s["created_at"]))

    # ------------------------------------------------------------------
    # SCRIPTS
    # ------------------------------------------------------------------
    async def create_script(self, script_data: Dict) -> str:
        sid = str(uuid.uuid4())
        self.scripts[sid] = {**script_data, "id": sid}
        return sid

    async def get_script(self, script_id: str) -> Optional[Dict]:
        s = self.scripts.get(script_id)
        return dict(s) if s else None

    async def update_script(self, script_id: str, updates: Dict) -> None:
        if script_id in self.scripts:
            self.scripts[script_id].update(updates)

    async def list_scripts(self, search: Optional[str] = None, tag: Optional[str] = None,
                            sort: str = "new", status: str = "published",
                            page: int = 1, limit: int = 24) -> Tuple[List[Dict], int]:
        scripts = [dict(s) for s in self.scripts.values() if s.get("status") == status]
        if search:
            s_lower = search.lower()
            scripts = [s for s in scripts if s_lower in s.get("title", "").lower()]
        if tag:
            scripts = [s for s in scripts if tag in s.get("tags", [])]
        total = len(scripts)
        return scripts[(page - 1) * limit: page * limit], total

    # ------------------------------------------------------------------
    # RELEASES
    # ------------------------------------------------------------------
    async def create_release(self, release_data: Dict) -> None:
        self.releases[release_data["version"]] = release_data

    async def get_active_release(self) -> Optional[Dict]:
        for r in self.releases.values():
            if r.get("active"):
                return dict(r)
        return None

    async def list_releases(self) -> List[Dict]:
        return [dict(r) for r in self.releases.values()]

    async def update_release(self, version: str, updates: Dict) -> None:
        if version in self.releases:
            self.releases[version].update(updates)

    # ------------------------------------------------------------------
    # API KEYS
    # ------------------------------------------------------------------
    async def create_api_key(self, key_data: Dict) -> str:
        kid = str(uuid.uuid4())
        self.api_keys[kid] = {**key_data, "key_id": kid}
        return kid

    async def get_api_key_by_hash(self, key_hash: str) -> Optional[Dict]:
        for k in self.api_keys.values():
            if k.get("key_hash") == key_hash and not k.get("revoked"):
                return dict(k)
        return None

    async def list_api_keys(self) -> List[Dict]:
        return [{k: v for k, v in key.items() if k != "key_hash"}
                for key in self.api_keys.values()]

    async def update_api_key(self, key_id: str, updates: Dict) -> None:
        if key_id in self.api_keys:
            self.api_keys[key_id].update(updates)

    # ------------------------------------------------------------------
    # AUDIT LOG
    # ------------------------------------------------------------------
    async def create_audit_log(self, entry: Dict) -> None:
        self.audit_logs.append(dict(entry))

    async def list_audit_logs(self, actor: Optional[str] = None, action: Optional[str] = None,
                               target: Optional[str] = None, page: int = 1,
                               limit: int = 50) -> Tuple[List[Dict], int]:
        logs = list(self.audit_logs)
        if actor:
            logs = [l for l in logs if l.get("actor") == actor]
        if action:
            logs = [l for l in logs if l.get("action") == action]
        if target:
            logs = [l for l in logs if l.get("target") == target]
        total = len(logs)
        return logs[(page - 1) * limit: page * limit], total

    # ------------------------------------------------------------------
    # ANNOUNCEMENTS
    # ------------------------------------------------------------------
    async def list_announcements(self, active_only: bool = True) -> List[Dict]:
        anns = [dict(a) for a in self.announcements.values()]
        if active_only:
            anns = [a for a in anns if a.get("active")]
        return anns

    async def create_announcement(self, data: Dict) -> str:
        aid = str(uuid.uuid4())
        self.announcements[aid] = {**data, "id": aid}
        return aid

    async def update_announcement(self, ann_id: str, updates: Dict) -> None:
        if ann_id in self.announcements:
            self.announcements[ann_id].update(updates)

    async def delete_announcement(self, ann_id: str) -> None:
        self.announcements.pop(ann_id, None)

    # ------------------------------------------------------------------
    # SETTINGS
    # ------------------------------------------------------------------
    async def get_settings(self) -> Dict:
        return dict(self._settings)

    async def update_settings(self, updates: Dict) -> None:
        self._settings.update(updates)

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------
    async def get_stats(self) -> Dict:
        return {
            "total_users": len(self.users),
            "active_subscriptions": sum(
                1 for u in self.users.values()
                if u.get("subscription", {}).get("status") == "active"
            ),
            "expiring_soon_7d": 0,
            "licenses": {
                "unused": sum(1 for l in self.licenses.values() if l["status"] == "unused"),
                "claimed": sum(1 for l in self.licenses.values() if l["status"] == "claimed"),
                "banned": sum(1 for l in self.licenses.values() if l["status"] == "banned"),
                "total": len(self.licenses),
            },
        }

    # ------------------------------------------------------------------
    # PRODUCTS
    # ------------------------------------------------------------------
    async def create_product(self, product_id: str, name: str, description: str = "", status: str = "active") -> Dict:
        if not hasattr(self, "products"):
            self.products = {}
        data = {
            "product_id": product_id,
            "name": name,
            "description": description,
            "status": status,
            "created_at": datetime.now(timezone.utc),
        }
        self.products[product_id] = data
        return dict(data)

    async def get_product(self, product_id: str) -> Optional[Dict]:
        if not hasattr(self, "products"):
            self.products = {}
        p = self.products.get(product_id)
        return dict(p) if p else None

    async def list_products(self) -> List[Dict]:
        if not hasattr(self, "products"):
            self.products = {}
        return [dict(p) for p in self.products.values()]

    async def delete_product(self, product_id: str) -> None:
        if hasattr(self, "products"):
            self.products.pop(product_id, None)



# ---------------------------------------------------------------------------
# pytest fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def db() -> InMemoryAdapter:
    return InMemoryAdapter()


@pytest_asyncio.fixture
async def client(db: InMemoryAdapter) -> AsyncGenerator[AsyncClient, None]:
    """HTTP test client with in-memory database."""
    set_db_adapter(db)

    # Import AFTER setting the adapter
    from app.main import create_app
    app = create_app()
    app.state.db = db
    set_db_adapter(db)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


@pytest_asyncio.fixture
async def verified_user(db: InMemoryAdapter) -> Dict:
    """A verified, non-banned regular user with password 'TestPassword123'."""
    uid = str(uuid.uuid4())
    await db.create_user(
        uid=uid,
        username="testuser",
        email="test@example.com",
        password_hash=hash_password("TestPassword123"),
    )
    await db.update_user(uid, {"email_verified": True})
    return await db.get_user_by_uid(uid)


@pytest_asyncio.fixture
async def admin_user(db: InMemoryAdapter) -> Dict:
    """A verified admin user with password 'AdminPassword123'."""
    uid = str(uuid.uuid4())
    await db.create_user(
        uid=uid,
        username="adminuser",
        email="admin@example.com",
        password_hash=hash_password("AdminPassword123"),
    )
    await db.update_user(uid, {"email_verified": True, "admin": True})
    return await db.get_user_by_uid(uid)


def auth_headers_for(user: Dict) -> Dict[str, str]:
    """
    Build Cookie + CSRF headers for a user.
    Bypasses the login flow for test isolation.
    """
    token = create_access_token(user["uid"], user.get("token_version", 1))
    csrf = generate_csrf_token()
    return {
        "Cookie": f"access_token={token}; csrf_token={csrf}",
        "X-CSRF-Token": csrf,
    }
