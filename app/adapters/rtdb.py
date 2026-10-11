"""
Firebase Realtime Database implementation of DatabaseAdapter.
Connects to https://prime-auth-69e92-default-rtdb.asia-southeast1.firebasedatabase.app
via firebase_admin.db using the server-side Admin SDK service account.
"""
import asyncio
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
import structlog

from firebase_admin import db as rtdb
from app.adapters.base import DatabaseAdapter
from app.core.errors import UsernameTaken, EmailTaken

log = structlog.get_logger()

_DEFAULT_SETTINGS = {
    "maintenance_mode": False,
    "registration_open": True,
    "hwid_reset_cooldown_days": 7,
    "max_sessions": 1,
    "loader_download_requires_subscription": False,
    "min_loader_version": "1.0.0",
    "current_loader_version": "1.0.0",
}

_DATETIME_KEYS = {
    "created_at",
    "updated_at",
    "last_login_at",
    "bound_at",
    "last_reset_at",
    "expires_at",
    "fixed_expires_at",
    "claimed_at",
    "starts_at",
    "ends_at",
    "banned_at",
    "last_heartbeat_at",
    "last_used_at",
    "used_at",
    "at",
}


def _serialize(obj: Any) -> Any:
    """Recursively convert datetime objects to ISO-8601 strings for RTDB JSON storage."""
    if isinstance(obj, datetime):
        if obj.tzinfo is None:
            obj = obj.replace(tzinfo=timezone.utc)
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(v) for v in obj]
    return obj


def _deserialize(obj: Any) -> Any:
    """Recursively convert ISO-8601 strings in known datetime fields back to datetime objects."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in _DATETIME_KEYS and isinstance(v, str):
                try:
                    dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    out[k] = dt
                except ValueError:
                    out[k] = v
            else:
                out[k] = _deserialize(v)
        return out
    if isinstance(obj, list):
        return [_deserialize(v) for v in obj]
    return obj


def _email_key(email: str) -> str:
    return hashlib.sha256(email.lower().strip().encode("utf-8")).hexdigest()


def _safe_key(key: str) -> str:
    return (
        key.replace(".", "_dot_")
        .replace("$", "_dlr_")
        .replace("#", "_hsh_")
        .replace("[", "_lb_")
        .replace("]", "_rb_")
        .replace("/", "_sl_")
    )


class RealtimeDatabaseAdapter(DatabaseAdapter):
    """
    Firebase Realtime Database implementation of DatabaseAdapter.
    All synchronous firebase_admin.db calls are executed via asyncio.to_thread.
    """

    def __init__(self, root_path: str = "/pruvate"):
        self._root = rtdb.reference(root_path)

    def _ref(self, path: str):
        return self._root.child(path)

    def _run(self, fn, *args, **kwargs):
        return asyncio.to_thread(fn, *args, **kwargs)

    # ==========================================================================
    # USERS
    # ==========================================================================

    async def get_user_by_uid(self, uid: str) -> Optional[Dict[str, Any]]:
        def _get():
            data = self._ref(f"users/{uid}").get()
            if not data:
                return None
            d = _deserialize(data)
            d["uid"] = uid
            d.setdefault("hwid", {"combined_hash": None, "components": [], "bound_at": None, "last_reset_at": None})
            d["hwid"].setdefault("components", [])
            d.setdefault("subscription", {"status": "none", "expires_at": None})
            return d
        return await self._run(_get)

    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        def _get():
            idx = self._ref(f"usernames/{username.lower()}").get()
            if not idx or not idx.get("uid"):
                return None
            uid = idx["uid"]
            data = self._ref(f"users/{uid}").get()
            if not data:
                return None
            d = _deserialize(data)
            d["uid"] = uid
            d.setdefault("hwid", {"combined_hash": None, "components": [], "bound_at": None, "last_reset_at": None})
            d["hwid"].setdefault("components", [])
            d.setdefault("subscription", {"status": "none", "expires_at": None})
            return d
        return await self._run(_get)

    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        def _get():
            ekey = _email_key(email)
            idx = self._ref(f"emails/{ekey}").get()
            if not idx or not idx.get("uid"):
                return None
            uid = idx["uid"]
            data = self._ref(f"users/{uid}").get()
            if not data:
                return None
            d = _deserialize(data)
            d["uid"] = uid
            d.setdefault("hwid", {"combined_hash": None, "components": [], "bound_at": None, "last_reset_at": None})
            d["hwid"].setdefault("components", [])
            d.setdefault("subscription", {"status": "none", "expires_at": None})
            return d
        return await self._run(_get)

    async def get_user_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        user = await self.get_user_by_username(identifier)
        if user:
            return user
        if "@" in identifier:
            return await self.get_user_by_email(identifier)
        return None

    async def create_user(
        self,
        uid: str,
        username: str,
        email: str,
        password_hash: str,
    ) -> Dict[str, Any]:
        def _create():
            from app.core.config import get_settings
            s = get_settings()
            now = datetime.now(timezone.utc)
            username_lower = username.lower()
            email_lower = email.lower().strip()
            ekey = _email_key(email_lower)

            # Atomic transaction on username index
            uname_ref = self._ref(f"usernames/{username_lower}")
            if uname_ref.get() is not None:
                raise UsernameTaken()

            email_ref = self._ref(f"emails/{ekey}")
            if email_ref.get() is not None:
                raise EmailTaken()

            won_username = {"ok": False}

            def claim_uname(current):
                if current is not None:
                    return current
                won_username["ok"] = True
                return {"uid": uid}

            uname_ref.transaction(claim_uname)
            if not won_username["ok"]:
                raise UsernameTaken()

            won_email = {"ok": False}

            def claim_email(current):
                if current is not None:
                    return current
                won_email["ok"] = True
                return {"uid": uid, "email": email_lower}

            email_ref.transaction(claim_email)
            if not won_email["ok"]:
                uname_ref.delete()
                raise EmailTaken()

            user_data = {
                "uid": uid,
                "username": username,
                "email": email_lower,
                "password_hash": password_hash,
                "admin": False,
                "banned": False,
                "ban_reason": None,
                "email_verified": not bool(s.smtp_host),
                "hwid": {
                    "combined_hash": None,
                    "components": [],
                    "bound_at": None,
                    "last_reset_at": None,
                },
                "subscription": {
                    "status": "none",
                    "expires_at": None,
                },
                "totp_secret_enc": None,
                "totp_enabled": False,
                "token_version": 1,
                "created_at": now,
                "last_login_at": None,
                "last_login_ip": None,
            }
            self._ref(f"users/{uid}").set(_serialize(user_data))
            return user_data

        return await self._run(_create)

    async def update_user(self, uid: str, updates: Dict[str, Any]) -> None:
        def _update():
            user_ref = self._ref(f"users/{uid}")
            current = user_ref.get()
            if not current:
                return
            for k, v in _serialize(updates).items():
                if "." in k:
                    parts = k.split(".")
                    target = current
                    for p in parts[:-1]:
                        if not isinstance(target.get(p), dict):
                            target[p] = {}
                        target = target[p]
                    target[parts[-1]] = v
                elif isinstance(v, dict) and isinstance(current.get(k), dict):
                    current[k].update(v)
                else:
                    current[k] = v
            user_ref.set(current)
        await self._run(_update)

    async def list_users(
        self,
        search: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]:
        def _list():
            raw = self._ref("users").get() or {}
            users = []
            for uid, data in raw.items():
                if not isinstance(data, dict):
                    continue
                d = _deserialize(data)
                d["uid"] = uid
                d.setdefault("hwid", {"combined_hash": None, "components": [], "bound_at": None, "last_reset_at": None})
                d["hwid"].setdefault("components", [])
                d.setdefault("subscription", {"status": "none", "expires_at": None})
                if search:
                    s = search.lower()
                    if not (
                        s in d.get("username", "").lower()
                        or s in d.get("email", "").lower()
                        or s in uid.lower()
                    ):
                        continue
                users.append(d)
            users.sort(key=lambda u: u.get("created_at") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
            total = len(users)
            start = (page - 1) * limit
            return users[start:start + limit], total
        return await self._run(_list)

    # ==========================================================================
    # WEB SESSIONS
    # ==========================================================================

    async def create_web_session(
        self,
        uid: str,
        token_hash: str,
        ip: str,
        user_agent: str,
        family_id: str,
    ) -> str:
        def _create():
            from app.core.config import get_settings
            s = get_settings()
            now = datetime.now(timezone.utc)
            session_id = str(uuid.uuid4())
            self._ref(f"web_sessions/{session_id}").set(_serialize({
                "session_id": session_id,
                "uid": uid,
                "token_hash": token_hash,
                "family_id": family_id,
                "ip": ip,
                "user_agent": user_agent[:255],
                "created_at": now,
                "last_used_at": now,
                "expires_at": now + timedelta(days=s.refresh_token_ttl_days),
                "revoked": False,
            }))
            return session_id
        return await self._run(_create)

    async def get_web_session_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        def _get():
            raw = self._ref("web_sessions").get() or {}
            for sid, sess in raw.items():
                if isinstance(sess, dict) and sess.get("token_hash") == token_hash and not sess.get("revoked"):
                    d = _deserialize(sess)
                    d["session_id"] = sid
                    return d
            return None
        return await self._run(_get)

    async def rotate_web_session(self, session_id: str, new_token_hash: str, ip: str) -> None:
        def _rotate():
            self._ref(f"web_sessions/{session_id}").update(_serialize({
                "token_hash": new_token_hash,
                "last_used_at": datetime.now(timezone.utc),
                "ip": ip,
            }))
        await self._run(_rotate)

    async def revoke_web_session(self, session_id: str) -> None:
        def _revoke():
            self._ref(f"web_sessions/{session_id}").update({"revoked": True})
        await self._run(_revoke)

    async def revoke_all_web_sessions(self, uid: str) -> None:
        def _revoke_all():
            raw = self._ref("web_sessions").get() or {}
            for sid, sess in raw.items():
                if isinstance(sess, dict) and sess.get("uid") == uid and not sess.get("revoked"):
                    self._ref(f"web_sessions/{sid}").update({"revoked": True})
        await self._run(_revoke_all)

    async def detect_refresh_token_reuse(self, family_id: str, token_hash: str) -> bool:
        def _detect():
            raw = self._ref("web_sessions").get() or {}
            for sess in raw.values():
                if (
                    isinstance(sess, dict)
                    and sess.get("family_id") == family_id
                    and sess.get("revoked")
                    and sess.get("token_hash") != token_hash
                ):
                    return True
            return False
        return await self._run(_detect)

    async def list_web_sessions(self, uid: str) -> List[Dict[str, Any]]:
        def _list():
            raw = self._ref("web_sessions").get() or {}
            result = []
            for sid, sess in raw.items():
                if isinstance(sess, dict) and sess.get("uid") == uid and not sess.get("revoked"):
                    d = _deserialize(sess)
                    d["session_id"] = sid
                    d.pop("token_hash", None)
                    result.append(d)
            result.sort(key=lambda x: x.get("last_used_at") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
            return result
        return await self._run(_list)

    # ==========================================================================
    # AUTH TOKENS
    # ==========================================================================

    async def store_token(
        self,
        token_type: str,
        uid: str,
        token_hash: str,
        expires_at: datetime,
        extra: Optional[Dict] = None,
    ) -> None:
        def _store():
            self._ref(f"auth_tokens/{token_hash}").set(_serialize({
                "type": token_type,
                "uid": uid,
                "token_hash": token_hash,
                "expires_at": expires_at,
                "extra": extra or {},
                "created_at": datetime.now(timezone.utc),
            }))
        await self._run(_store)

    async def consume_token(self, token_type: str, token_hash: str) -> Optional[Dict[str, Any]]:
        def _consume():
            ref = self._ref(f"auth_tokens/{token_hash}")
            data = ref.get()
            if not data:
                return None
            ref.delete()
            d = _deserialize(data)
            if d.get("type") != token_type:
                return None
            exp = d.get("expires_at")
            if isinstance(exp, datetime) and datetime.now(timezone.utc) > exp:
                return None
            return d
        return await self._run(_consume)

    # ==========================================================================
    # NONCES
    # ==========================================================================

    async def check_and_store_nonce(self, nonce: str, ttl_seconds: int) -> bool:
        def _check():
            skey = _safe_key(nonce)
            ref = self._ref(f"nonces/{skey}")
            now = datetime.now(timezone.utc)
            existing = ref.get()
            if existing:
                d = _deserialize(existing)
                exp = d.get("expires_at")
                if isinstance(exp, datetime) and now < exp:
                    return False
            ref.set(_serialize({
                "used_at": now,
                "expires_at": now + timedelta(seconds=ttl_seconds),
            }))
            return True
        return await self._run(_check)

    # ==========================================================================
    # LICENSES
    # ==========================================================================

    async def create_license(
        self,
        license_id: str,
        key_lookup: str,
        key_enc: str,
        prefix: str,
        duration_days: Optional[int],
        fixed_expires_at: Optional[datetime],
        lifetime: bool,
        discord_id: Optional[str],
        note: Optional[str],
        batch_id: Optional[str],
        created_by: str,
        product_id: Optional[str] = "default",
        product_name: Optional[str] = "Default Product",
    ) -> Dict[str, Any]:
        def _create():
            now = datetime.now(timezone.utc)
            data = {
                "id": license_id,
                "key_lookup": key_lookup,
                "key_enc": key_enc,
                "prefix": prefix,
                "duration_days": duration_days,
                "fixed_expires_at": fixed_expires_at,
                "lifetime": lifetime,
                "status": "unused",
                "discord_id": discord_id,
                "note": note,
                "batch_id": batch_id,
                "created_by": created_by,
                "created_at": now,
                "product_id": product_id or "default",
                "product_name": product_name or "Default Product",
                "claimed_by": None,
                "claimed_at": None,
                "starts_at": None,
                "ends_at": None,
                "banned_at": None,
                "ban_reason": None,
            }
            self._ref(f"licenses/{license_id}").set(_serialize(data))
            return data
        return await self._run(_create)

    async def get_license_by_lookup(self, key_lookup: str) -> Optional[Dict[str, Any]]:
        def _get():
            raw = self._ref("licenses").get() or {}
            for lid, lic in raw.items():
                if isinstance(lic, dict) and lic.get("key_lookup") == key_lookup:
                    d = _deserialize(lic)
                    d["id"] = lid
                    return d
            return None
        return await self._run(_get)

    async def get_license_by_id(self, license_id: str) -> Optional[Dict[str, Any]]:
        def _get():
            lic = self._ref(f"licenses/{license_id}").get()
            if not lic:
                return None
            d = _deserialize(lic)
            d["id"] = license_id
            return d
        return await self._run(_get)

    async def claim_license_atomic(
        self,
        license_id: str,
        uid: str,
        starts_at: datetime,
        ends_at: Optional[datetime],
    ) -> bool:
        def _claim():
            ref = self._ref(f"licenses/{license_id}")
            won = {"ok": False}
            now_iso = _serialize(datetime.now(timezone.utc))
            starts_iso = _serialize(starts_at)
            ends_iso = _serialize(ends_at)

            def _txn(current):
                if current is None:
                    return current
                if current.get("status") != "unused":
                    won["ok"] = False
                    return current
                current["status"] = "claimed"
                current["claimed_by"] = uid
                current["claimed_at"] = now_iso
                current["starts_at"] = starts_iso
                current["ends_at"] = ends_iso
                won["ok"] = True
                return current

            ref.transaction(_txn)
            return won["ok"]
        return await self._run(_claim)

    async def update_license(self, license_id: str, updates: Dict[str, Any]) -> None:
        def _update():
            self._ref(f"licenses/{license_id}").update(_serialize(updates))
        await self._run(_update)

    async def list_licenses(
        self,
        search: Optional[str] = None,
        status: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]:
        def _list():
            raw = self._ref("licenses").get() or {}
            licenses = []
            for lid, lic in raw.items():
                if not isinstance(lic, dict):
                    continue
                d = _deserialize(lic)
                d["id"] = lid
                if status and d.get("status") != status:
                    continue
                if search:
                    s = search.lower()
                    if not (
                        s in lid.lower()
                        or s in (d.get("discord_id") or "").lower()
                        or s in (d.get("claimed_by") or "").lower()
                        or s in (d.get("prefix") or "").lower()
                    ):
                        continue
                licenses.append(d)
            licenses.sort(key=lambda x: x.get("created_at") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
            total = len(licenses)
            start = (page - 1) * limit
            return licenses[start:start + limit], total
        return await self._run(_list)

    async def get_user_active_licenses(self, uid: str) -> List[Dict[str, Any]]:
        def _get():
            raw = self._ref("licenses").get() or {}
            result = []
            for lid, lic in raw.items():
                if isinstance(lic, dict) and lic.get("claimed_by") == uid and lic.get("status") == "claimed":
                    d = _deserialize(lic)
                    d["id"] = lid
                    result.append(d)
            return result
        return await self._run(_get)

    # ==========================================================================
    # LOADER SESSIONS
    # ==========================================================================

    async def create_loader_session(
        self,
        session_id: str,
        uid: str,
        token_hash: str,
        hwid_hash: str,
        ip: str,
        app_version: str,
        expires_at: datetime,
    ) -> None:
        def _create():
            now = datetime.now(timezone.utc)
            self._ref(f"sessions/{session_id}").set(_serialize({
                "session_id": session_id,
                "uid": uid,
                "token_hash": token_hash,
                "hwid_hash": hwid_hash,
                "ip": ip,
                "app_version": app_version,
                "created_at": now,
                "last_heartbeat_at": now,
                "expires_at": expires_at,
                "last_seq": 0,
                "revoked": False,
            }))
        await self._run(_create)

    async def get_loader_session_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        def _get():
            raw = self._ref("sessions").get() or {}
            for sid, sess in raw.items():
                if isinstance(sess, dict) and sess.get("token_hash") == token_hash and not sess.get("revoked"):
                    d = _deserialize(sess)
                    d["session_id"] = sid
                    return d
            return None
        return await self._run(_get)

    async def update_loader_session(self, session_id: str, updates: Dict[str, Any]) -> None:
        def _update():
            self._ref(f"sessions/{session_id}").update(_serialize(updates))
        await self._run(_update)

    async def revoke_loader_session(self, session_id: str) -> None:
        def _revoke():
            self._ref(f"sessions/{session_id}").update({"revoked": True})
        await self._run(_revoke)

    async def revoke_user_loader_sessions(self, uid: str) -> None:
        def _revoke():
            raw = self._ref("sessions").get() or {}
            for sid, sess in raw.items():
                if isinstance(sess, dict) and sess.get("uid") == uid and not sess.get("revoked"):
                    self._ref(f"sessions/{sid}").update({"revoked": True})
        await self._run(_revoke)

    async def count_active_loader_sessions(self, uid: str) -> int:
        def _count():
            raw = self._ref("sessions").get() or {}
            now = datetime.now(timezone.utc)
            count = 0
            for sess in raw.values():
                if isinstance(sess, dict) and sess.get("uid") == uid and not sess.get("revoked"):
                    d = _deserialize(sess)
                    exp = d.get("expires_at")
                    if isinstance(exp, datetime) and exp > now:
                        count += 1
            return count
        return await self._run(_count)

    async def get_oldest_loader_session(self, uid: str) -> Optional[Dict[str, Any]]:
        def _get():
            raw = self._ref("sessions").get() or {}
            sessions = []
            for sid, sess in raw.items():
                if isinstance(sess, dict) and sess.get("uid") == uid and not sess.get("revoked"):
                    d = _deserialize(sess)
                    d["session_id"] = sid
                    sessions.append(d)
            if not sessions:
                return None
            return min(sessions, key=lambda s: s.get("created_at") or datetime.min.replace(tzinfo=timezone.utc))
        return await self._run(_get)

    # ==========================================================================
    # SCRIPTS
    # ==========================================================================

    async def create_script(self, script_data: Dict[str, Any]) -> str:
        def _create():
            script_id = str(uuid.uuid4())
            data = {**script_data, "id": script_id}
            self._ref(f"scripts/{script_id}").set(_serialize(data))
            return script_id
        return await self._run(_create)

    async def get_script(self, script_id: str) -> Optional[Dict[str, Any]]:
        def _get():
            data = self._ref(f"scripts/{script_id}").get()
            if not data:
                return None
            d = _deserialize(data)
            d["id"] = script_id
            d.setdefault("tags", [])
            return d
        return await self._run(_get)

    async def update_script(self, script_id: str, updates: Dict[str, Any]) -> None:
        def _update():
            self._ref(f"scripts/{script_id}").update(_serialize(updates))
        await self._run(_update)

    async def list_scripts(
        self,
        search: Optional[str] = None,
        tag: Optional[str] = None,
        sort: str = "new",
        status: str = "published",
        page: int = 1,
        limit: int = 24,
    ) -> Tuple[List[Dict[str, Any]], int]:
        def _list():
            raw = self._ref("scripts").get() or {}
            scripts = []
            for sid, sdata in raw.items():
                if not isinstance(sdata, dict):
                    continue
                d = _deserialize(sdata)
                d["id"] = sid
                d.setdefault("tags", [])
                if d.get("status") != status:
                    continue
                if tag and tag not in d.get("tags", []):
                    continue
                if search:
                    s = search.lower()
                    if not (s in d.get("title", "").lower() or s in d.get("description", "").lower()):
                        continue
                scripts.append(d)
            sort_field = {"new": "created_at", "top": "likes", "downloads": "downloads"}.get(sort, "created_at")
            if sort_field == "created_at":
                scripts.sort(key=lambda x: x.get("created_at") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
            else:
                scripts.sort(key=lambda x: x.get(sort_field, 0), reverse=True)
            total = len(scripts)
            start = (page - 1) * limit
            return scripts[start:start + limit], total
        return await self._run(_list)

    # ==========================================================================
    # RELEASES
    # ==========================================================================

    async def create_release(self, release_data: Dict[str, Any]) -> None:
        def _create():
            vkey = _safe_key(release_data["version"])
            self._ref(f"releases/{vkey}").set(_serialize(release_data))
        await self._run(_create)

    async def get_active_release(self, ) -> Optional[Dict[str, Any]]:
        def _get():
            raw = self._ref("releases").get() or {}
            active = [
                _deserialize(r)
                for r in raw.values()
                if isinstance(r, dict) and r.get("active")
            ]
            if not active:
                return None
            active.sort(key=lambda x: x.get("created_at") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
            return active[0]
        return await self._run(_get)

    async def list_releases(self) -> List[Dict[str, Any]]:
        def _list():
            raw = self._ref("releases").get() or {}
            res = [_deserialize(r) for r in raw.values() if isinstance(r, dict)]
            res.sort(key=lambda x: x.get("created_at") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
            return res
        return await self._run(_list)

    async def update_release(self, version: str, updates: Dict[str, Any]) -> None:
        def _update():
            vkey = _safe_key(version)
            self._ref(f"releases/{vkey}").update(_serialize(updates))
        await self._run(_update)

    # ==========================================================================
    # API KEYS
    # ==========================================================================

    async def create_api_key(self, key_data: Dict[str, Any]) -> str:
        def _create():
            kid = str(uuid.uuid4())
            data = {**key_data, "key_id": kid}
            self._ref(f"api_keys/{kid}").set(_serialize(data))
            return kid
        return await self._run(_create)

    async def get_api_key_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        def _get():
            raw = self._ref("api_keys").get() or {}
            for kid, kdata in raw.items():
                if isinstance(kdata, dict) and kdata.get("key_hash") == key_hash and not kdata.get("revoked"):
                    d = _deserialize(kdata)
                    d["key_id"] = kid
                    return d
            return None
        return await self._run(_get)

    async def list_api_keys(self) -> List[Dict[str, Any]]:
        def _list():
            raw = self._ref("api_keys").get() or {}
            res = []
            for kid, kdata in raw.items():
                if isinstance(kdata, dict):
                    d = _deserialize(kdata)
                    d["key_id"] = kid
                    d.pop("key_hash", None)
                    res.append(d)
            return res
        return await self._run(_list)

    async def update_api_key(self, key_id: str, updates: Dict[str, Any]) -> None:
        def _update():
            self._ref(f"api_keys/{key_id}").update(_serialize(updates))
        await self._run(_update)

    # ==========================================================================
    # AUDIT LOG
    # ==========================================================================

    async def create_audit_log(self, entry: Dict[str, Any]) -> None:
        def _create():
            lid = str(uuid.uuid4())
            self._ref(f"audit_logs/{lid}").set(_serialize({**entry, "log_id": lid}))
        await self._run(_create)

    async def list_audit_logs(
        self,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        target: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]:
        def _list():
            raw = self._ref("audit_logs").get() or {}
            logs = []
            for lid, ldata in raw.items():
                if not isinstance(ldata, dict):
                    continue
                d = _deserialize(ldata)
                d["log_id"] = lid
                if actor and d.get("actor") != actor:
                    continue
                if action and d.get("action") != action:
                    continue
                if target and d.get("target") != target:
                    continue
                logs.append(d)
            logs.sort(key=lambda x: x.get("at") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
            total = len(logs)
            start = (page - 1) * limit
            return logs[start:start + limit], total
        return await self._run(_list)

    # ==========================================================================
    # ANNOUNCEMENTS
    # ==========================================================================

    async def list_announcements(self, active_only: bool = True) -> List[Dict[str, Any]]:
        def _list():
            raw = self._ref("announcements").get() or {}
            res = []
            for aid, adata in raw.items():
                if not isinstance(adata, dict):
                    continue
                d = _deserialize(adata)
                d["id"] = aid
                if active_only and not d.get("active"):
                    continue
                res.append(d)
            res.sort(key=lambda x: x.get("created_at") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
            return res
        return await self._run(_list)

    async def create_announcement(self, data: Dict[str, Any]) -> str:
        def _create():
            aid = str(uuid.uuid4())
            self._ref(f"announcements/{aid}").set(_serialize({**data, "id": aid}))
            return aid
        return await self._run(_create)

    async def update_announcement(self, ann_id: str, updates: Dict[str, Any]) -> None:
        def _update():
            self._ref(f"announcements/{ann_id}").update(_serialize(updates))
        await self._run(_update)

    async def delete_announcement(self, ann_id: str) -> None:
        def _delete():
            self._ref(f"announcements/{ann_id}").delete()
        await self._run(_delete)

    # ==========================================================================
    # SETTINGS
    # ==========================================================================

    async def get_settings(self) -> Dict[str, Any]:
        def _get():
            data = self._ref("settings/global").get()
            if not data or not isinstance(data, dict):
                return dict(_DEFAULT_SETTINGS)
            return {**_DEFAULT_SETTINGS, **data}
        return await self._run(_get)

    async def update_settings(self, updates: Dict[str, Any]) -> None:
        def _update():
            self._ref("settings/global").update(_serialize(updates))
        await self._run(_update)

    # ==========================================================================
    # STATS
    # ==========================================================================

    async def get_stats(self) -> Dict[str, Any]:
        def _get():
            users_raw = self._ref("users").get() or {}
            licenses_raw = self._ref("licenses").get() or {}
            now = datetime.now(timezone.utc)
            in_7_days = now + timedelta(days=7)

            unused = 0
            claimed = 0
            banned = 0
            for lic in licenses_raw.values():
                if not isinstance(lic, dict):
                    continue
                st = lic.get("status")
                if st == "unused":
                    unused += 1
                elif st == "claimed":
                    claimed += 1
                elif st == "banned":
                    banned += 1

            active_subs = 0
            expiring_soon = 0
            for u in users_raw.values():
                if not isinstance(u, dict):
                    continue
                du = _deserialize(u)
                sub = du.get("subscription", {})
                if sub.get("status") == "active":
                    active_subs += 1
                    exp = sub.get("expires_at")
                    if isinstance(exp, datetime) and exp <= in_7_days:
                        expiring_soon += 1

            return {
                "total_users": len(users_raw),
                "active_subscriptions": active_subs,
                "expiring_soon_7d": expiring_soon,
                "licenses": {
                    "unused": unused,
                    "claimed": claimed,
                    "banned": banned,
                    "total": len(licenses_raw),
                },
            }
        return await self._run(_get)

    # ==========================================================================
    # PRODUCTS
    # ==========================================================================

    async def create_product(
        self,
        product_id: str,
        name: str,
        description: str = "",
        status: str = "active",
    ) -> Dict[str, Any]:
        def _create():
            now = datetime.now(timezone.utc)
            skey = _safe_key(product_id)
            data = {
                "product_id": product_id,
                "name": name,
                "description": description,
                "status": status,
                "created_at": now,
            }
            self._ref(f"products/{skey}").set(_serialize(data))
            return data
        return await self._run(_create)

    async def get_product(self, product_id: str) -> Optional[Dict[str, Any]]:
        def _get():
            skey = _safe_key(product_id)
            data = self._ref(f"products/{skey}").get()
            if not data:
                return None
            return _deserialize(data)
        return await self._run(_get)

    async def list_products(self) -> List[Dict[str, Any]]:
        def _list():
            raw = self._ref("products").get() or {}
            res = []
            for pdata in raw.values():
                if isinstance(pdata, dict):
                    res.append(_deserialize(pdata))
            res.sort(key=lambda x: x.get("created_at") or datetime.min.replace(tzinfo=timezone.utc), reverse=False)
            return res
        return await self._run(_list)

    async def delete_product(self, product_id: str) -> None:
        def _delete():
            skey = _safe_key(product_id)
            self._ref(f"products/{skey}").delete()
        await self._run(_delete)

