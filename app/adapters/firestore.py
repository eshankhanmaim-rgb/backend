import asyncio
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
import structlog

from app.adapters.base import DatabaseAdapter
from app.core.errors import UsernameTaken, EmailTaken, InternalError

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


class FirestoreAdapter(DatabaseAdapter):
    """
    Firestore implementation of DatabaseAdapter.
    Uses firebase_admin SDK. All heavy I/O wrapped in asyncio.to_thread.
    """

    def __init__(self, db):
        """db = firebase_admin.firestore.client()"""
        self._db = db

    def _run(self, fn, *args, **kwargs):
        """Run a synchronous Firestore call in a thread pool."""
        return asyncio.to_thread(fn, *args, **kwargs)

    # ==========================================================================
    # USERS
    # ==========================================================================

    async def get_user_by_uid(self, uid: str) -> Optional[Dict[str, Any]]:
        def _get():
            doc = self._db.collection("users").document(uid).get()
            if not doc.exists:
                return None
            d = doc.to_dict()
            d["uid"] = doc.id
            return d
        return await self._run(_get)

    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        def _get():
            idx = self._db.collection("usernames").document(username.lower()).get()
            if not idx.exists:
                return None
            uid = idx.to_dict().get("uid")
            if not uid:
                return None
            doc = self._db.collection("users").document(uid).get()
            if not doc.exists:
                return None
            d = doc.to_dict()
            d["uid"] = doc.id
            return d
        return await self._run(_get)

    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        def _get():
            normalized = email.lower().strip()
            idx = self._db.collection("emails").document(normalized).get()
            if not idx.exists:
                return None
            uid = idx.to_dict().get("uid")
            if not uid:
                return None
            doc = self._db.collection("users").document(uid).get()
            if not doc.exists:
                return None
            d = doc.to_dict()
            d["uid"] = doc.id
            return d
        return await self._run(_get)

    async def get_user_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        # Try as username first, then as email
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
            from google.cloud import firestore as gc_firestore
            from app.core.config import get_settings
            s = get_settings()
            now = datetime.now(timezone.utc)
            username_lower = username.lower()
            email_lower = email.lower().strip()

            username_ref = self._db.collection("usernames").document(username_lower)
            email_ref = self._db.collection("emails").document(email_lower)
            user_ref = self._db.collection("users").document(uid)

            @gc_firestore.transactional
            def txn(transaction):
                u_snap = username_ref.get(transaction=transaction)
                if u_snap.exists:
                    raise UsernameTaken()
                e_snap = email_ref.get(transaction=transaction)
                if e_snap.exists:
                    raise EmailTaken()

                user_data = {
                    "username": username,
                    "email": email_lower,
                    "password_hash": password_hash,
                    "admin": False,
                    "banned": False,
                    "ban_reason": None,
                    "email_verified": (s.app_env == "development" and not bool(s.smtp_host)),
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
                transaction.set(user_ref, user_data)
                transaction.set(username_ref, {"uid": uid})
                transaction.set(email_ref, {"uid": uid})
                return user_data

            result = txn(self._db.transaction())
            result["uid"] = uid
            return result

        return await self._run(_create)

    async def update_user(self, uid: str, updates: Dict[str, Any]) -> None:
        def _update():
            self._db.collection("users").document(uid).update(updates)
        await self._run(_update)

    async def list_users(
        self,
        search: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]:
        def _list():
            query = self._db.collection("users").order_by("created_at", direction="DESCENDING")
            docs = list(query.stream())
            users = []
            for doc in docs:
                d = doc.to_dict()
                d["uid"] = doc.id
                # Client-side search filter (Firestore doesn't support full-text)
                if search:
                    s = search.lower()
                    if not (
                        s in d.get("username", "").lower()
                        or s in d.get("email", "").lower()
                        or s in doc.id.lower()
                    ):
                        continue
                users.append(d)
            total = len(users)
            start = (page - 1) * limit
            return users[start:start + limit], total
        return await self._run(_list)

    # ==========================================================================
    # WEB SESSIONS (refresh tokens)
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
            now = datetime.now(timezone.utc)
            from app.core.config import get_settings
            s = get_settings()
            session_id = str(uuid.uuid4())
            self._db.collection("web_sessions").document(session_id).set({
                "uid": uid,
                "token_hash": token_hash,
                "family_id": family_id,
                "ip": ip,
                "user_agent": user_agent[:255],
                "created_at": now,
                "last_used_at": now,
                "expires_at": now + timedelta(days=s.refresh_token_ttl_days),
                "revoked": False,
                "reuse_detected": False,
            })
            return session_id
        return await self._run(_create)

    async def get_web_session_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        def _get():
            docs = list(
                self._db.collection("web_sessions")
                .where("token_hash", "==", token_hash)
                .where("revoked", "==", False)
                .limit(1)
                .stream()
            )
            if not docs:
                return None
            d = docs[0].to_dict()
            d["session_id"] = docs[0].id
            return d
        return await self._run(_get)

    async def rotate_web_session(
        self,
        session_id: str,
        new_token_hash: str,
        ip: str,
    ) -> None:
        def _rotate():
            self._db.collection("web_sessions").document(session_id).update({
                "token_hash": new_token_hash,
                "last_used_at": datetime.now(timezone.utc),
                "ip": ip,
            })
        await self._run(_rotate)

    async def revoke_web_session(self, session_id: str) -> None:
        def _revoke():
            self._db.collection("web_sessions").document(session_id).update({"revoked": True})
        await self._run(_revoke)

    async def revoke_all_web_sessions(self, uid: str) -> None:
        def _revoke_all():
            docs = self._db.collection("web_sessions").where("uid", "==", uid).where("revoked", "==", False).stream()
            batch = self._db.batch()
            for doc in docs:
                batch.update(doc.reference, {"revoked": True})
            batch.commit()
        await self._run(_revoke_all)

    async def detect_refresh_token_reuse(self, family_id: str, token_hash: str) -> bool:
        def _detect():
            docs = list(
                self._db.collection("web_sessions")
                .where("family_id", "==", family_id)
                .stream()
            )
            for doc in docs:
                d = doc.to_dict()
                # If there's a revoked session in this family with a DIFFERENT hash,
                # something is replaying old tokens
                if d.get("revoked") and d.get("token_hash") != token_hash:
                    return True
            return False
        return await self._run(_detect)

    async def list_web_sessions(self, uid: str) -> List[Dict[str, Any]]:
        def _list():
            docs = (
                self._db.collection("web_sessions")
                .where("uid", "==", uid)
                .where("revoked", "==", False)
                .order_by("last_used_at", direction="DESCENDING")
                .stream()
            )
            result = []
            for doc in docs:
                d = doc.to_dict()
                d["session_id"] = doc.id
                d.pop("token_hash", None)  # Never expose the hash
                result.append(d)
            return result
        return await self._run(_list)

    # ==========================================================================
    # EMAIL VERIFY / PASSWORD RESET TOKENS
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
            self._db.collection("auth_tokens").document(token_hash).set({
                "type": token_type,
                "uid": uid,
                "token_hash": token_hash,
                "expires_at": expires_at,
                "extra": extra or {},
                "created_at": datetime.now(timezone.utc),
            })
        await self._run(_store)

    async def consume_token(
        self,
        token_type: str,
        token_hash: str,
    ) -> Optional[Dict[str, Any]]:
        def _consume():
            from google.cloud import firestore as gc_firestore
            ref = self._db.collection("auth_tokens").document(token_hash)
            @gc_firestore.transactional
            def txn(transaction):
                snap = ref.get(transaction=transaction)
                if not snap.exists:
                    return None
                d = snap.to_dict()
                if d.get("type") != token_type:
                    return None
                # Check expiry
                expires_at = d.get("expires_at")
                if expires_at:
                    if hasattr(expires_at, 'timestamp'):
                        exp_ts = expires_at.timestamp()
                    else:
                        exp_ts = expires_at
                    if datetime.now(timezone.utc).timestamp() > exp_ts:
                        transaction.delete(ref)
                        return None
                transaction.delete(ref)
                return d
            return txn(self._db.transaction())
        return await self._run(_consume)

    # ==========================================================================
    # NONCES
    # ==========================================================================

    async def check_and_store_nonce(self, nonce: str, ttl_seconds: int) -> bool:
        def _check():
            from google.cloud import firestore as gc_firestore
            ref = self._db.collection("nonces").document(nonce)
            @gc_firestore.transactional
            def txn(transaction):
                snap = ref.get(transaction=transaction)
                if snap.exists:
                    return False
                now = datetime.now(timezone.utc)
                transaction.set(ref, {
                    "used_at": now,
                    "expires_at": now + timedelta(seconds=ttl_seconds),
                })
                return True
            return txn(self._db.transaction())
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
            self._db.collection("licenses").document(license_id).set(data)
            data["id"] = license_id
            return data
        return await self._run(_create)

    async def get_license_by_lookup(self, key_lookup: str) -> Optional[Dict[str, Any]]:
        def _get():
            docs = list(
                self._db.collection("licenses")
                .where("key_lookup", "==", key_lookup)
                .limit(1)
                .stream()
            )
            if not docs:
                return None
            d = docs[0].to_dict()
            d["id"] = docs[0].id
            return d
        return await self._run(_get)

    async def get_license_by_id(self, license_id: str) -> Optional[Dict[str, Any]]:
        def _get():
            doc = self._db.collection("licenses").document(license_id).get()
            if not doc.exists:
                return None
            d = doc.to_dict()
            d["id"] = doc.id
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
            from google.cloud import firestore as gc_firestore
            ref = self._db.collection("licenses").document(license_id)
            @gc_firestore.transactional
            def txn(transaction):
                snap = ref.get(transaction=transaction)
                if not snap.exists:
                    return False
                d = snap.to_dict()
                if d.get("status") != "unused":
                    return False
                now = datetime.now(timezone.utc)
                transaction.update(ref, {
                    "status": "claimed",
                    "claimed_by": uid,
                    "claimed_at": now,
                    "starts_at": starts_at,
                    "ends_at": ends_at,
                })
                return True
            return txn(self._db.transaction())
        return await self._run(_claim)

    async def update_license(self, license_id: str, updates: Dict[str, Any]) -> None:
        def _update():
            self._db.collection("licenses").document(license_id).update(updates)
        await self._run(_update)

    async def list_licenses(
        self,
        search: Optional[str] = None,
        status: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]:
        def _list():
            query = self._db.collection("licenses").order_by("created_at", direction="DESCENDING")
            if status:
                query = query.where("status", "==", status)
            docs = list(query.stream())
            licenses = []
            for doc in docs:
                d = doc.to_dict()
                d["id"] = doc.id
                if search:
                    s = search.lower()
                    if not (
                        s in doc.id.lower()
                        or s in (d.get("discord_id") or "").lower()
                        or s in (d.get("claimed_by") or "").lower()
                        or s in (d.get("prefix") or "").lower()
                    ):
                        continue
                licenses.append(d)
            total = len(licenses)
            start = (page - 1) * limit
            return licenses[start:start + limit], total
        return await self._run(_list)

    async def get_user_active_licenses(self, uid: str) -> List[Dict[str, Any]]:
        def _get():
            docs = (
                self._db.collection("licenses")
                .where("claimed_by", "==", uid)
                .where("status", "==", "claimed")
                .stream()
            )
            result = []
            for doc in docs:
                d = doc.to_dict()
                d["id"] = doc.id
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
            self._db.collection("sessions").document(session_id).set({
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
            })
        await self._run(_create)

    async def get_loader_session_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        def _get():
            docs = list(
                self._db.collection("sessions")
                .where("token_hash", "==", token_hash)
                .where("revoked", "==", False)
                .limit(1)
                .stream()
            )
            if not docs:
                return None
            d = docs[0].to_dict()
            d["session_id"] = docs[0].id
            return d
        return await self._run(_get)

    async def update_loader_session(self, session_id: str, updates: Dict[str, Any]) -> None:
        def _update():
            self._db.collection("sessions").document(session_id).update(updates)
        await self._run(_update)

    async def revoke_loader_session(self, session_id: str) -> None:
        def _revoke():
            self._db.collection("sessions").document(session_id).update({"revoked": True})
        await self._run(_revoke)

    async def revoke_user_loader_sessions(self, uid: str) -> None:
        def _revoke():
            docs = self._db.collection("sessions").where("uid", "==", uid).where("revoked", "==", False).stream()
            batch = self._db.batch()
            for doc in docs:
                batch.update(doc.reference, {"revoked": True})
            batch.commit()
        await self._run(_revoke)

    async def count_active_loader_sessions(self, uid: str) -> int:
        def _count():
            docs = list(
                self._db.collection("sessions")
                .where("uid", "==", uid)
                .where("revoked", "==", False)
                .stream()
            )
            now = datetime.now(timezone.utc)
            return sum(
                1 for doc in docs
                if _ts_to_dt(doc.to_dict().get("expires_at")) > now
            )
        return await self._run(_count)

    async def get_oldest_loader_session(self, uid: str) -> Optional[Dict[str, Any]]:
        def _get():
            docs = list(
                self._db.collection("sessions")
                .where("uid", "==", uid)
                .where("revoked", "==", False)
                .order_by("created_at", direction="ASCENDING")
                .limit(1)
                .stream()
            )
            if not docs:
                return None
            d = docs[0].to_dict()
            d["session_id"] = docs[0].id
            return d
        return await self._run(_get)

    # ==========================================================================
    # SCRIPTS
    # ==========================================================================

    async def create_script(self, script_data: Dict[str, Any]) -> str:
        def _create():
            script_id = str(uuid.uuid4())
            self._db.collection("scripts").document(script_id).set(script_data)
            return script_id
        return await self._run(_create)

    async def get_script(self, script_id: str) -> Optional[Dict[str, Any]]:
        def _get():
            doc = self._db.collection("scripts").document(script_id).get()
            if not doc.exists:
                return None
            d = doc.to_dict()
            d["id"] = doc.id
            return d
        return await self._run(_get)

    async def update_script(self, script_id: str, updates: Dict[str, Any]) -> None:
        def _update():
            self._db.collection("scripts").document(script_id).update(updates)
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
            sort_field = {"new": "created_at", "top": "likes", "downloads": "downloads"}.get(sort, "created_at")
            query = (
                self._db.collection("scripts")
                .where("status", "==", status)
                .order_by(sort_field, direction="DESCENDING")
            )
            if tag:
                query = query.where("tags", "array_contains", tag)
            docs = list(query.stream())
            scripts = []
            for doc in docs:
                d = doc.to_dict()
                d["id"] = doc.id
                if search:
                    s = search.lower()
                    if not (s in d.get("title", "").lower() or s in d.get("description", "").lower()):
                        continue
                scripts.append(d)
            total = len(scripts)
            start = (page - 1) * limit
            return scripts[start:start + limit], total
        return await self._run(_list)

    # ==========================================================================
    # RELEASES
    # ==========================================================================

    async def create_release(self, release_data: Dict[str, Any]) -> None:
        def _create():
            version = release_data["version"]
            self._db.collection("releases").document(version).set(release_data)
        await self._run(_create)

    async def get_active_release(self) -> Optional[Dict[str, Any]]:
        def _get():
            docs = list(
                self._db.collection("releases")
                .where("active", "==", True)
                .order_by("created_at", direction="DESCENDING")
                .limit(1)
                .stream()
            )
            if not docs:
                return None
            d = docs[0].to_dict()
            d["version"] = docs[0].id
            return d
        return await self._run(_get)

    async def list_releases(self) -> List[Dict[str, Any]]:
        def _list():
            docs = self._db.collection("releases").order_by("created_at", direction="DESCENDING").stream()
            result = []
            for doc in docs:
                d = doc.to_dict()
                d["version"] = doc.id
                result.append(d)
            return result
        return await self._run(_list)

    async def update_release(self, version: str, updates: Dict[str, Any]) -> None:
        def _update():
            self._db.collection("releases").document(version).update(updates)
        await self._run(_update)

    # ==========================================================================
    # API KEYS
    # ==========================================================================

    async def create_api_key(self, key_data: Dict[str, Any]) -> str:
        def _create():
            key_id = str(uuid.uuid4())
            self._db.collection("api_keys").document(key_id).set(key_data)
            return key_id
        return await self._run(_create)

    async def get_api_key_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        def _get():
            docs = list(
                self._db.collection("api_keys")
                .where("key_hash", "==", key_hash)
                .where("revoked", "==", False)
                .limit(1)
                .stream()
            )
            if not docs:
                return None
            d = docs[0].to_dict()
            d["key_id"] = docs[0].id
            return d
        return await self._run(_get)

    async def list_api_keys(self) -> List[Dict[str, Any]]:
        def _list():
            docs = self._db.collection("api_keys").order_by("created_at", direction="DESCENDING").stream()
            result = []
            for doc in docs:
                d = doc.to_dict()
                d["key_id"] = doc.id
                d.pop("key_hash", None)  # never expose hash
                result.append(d)
            return result
        return await self._run(_list)

    async def update_api_key(self, key_id: str, updates: Dict[str, Any]) -> None:
        def _update():
            self._db.collection("api_keys").document(key_id).update(updates)
        await self._run(_update)

    # ==========================================================================
    # AUDIT LOG
    # ==========================================================================

    async def create_audit_log(self, entry: Dict[str, Any]) -> None:
        def _create():
            self._db.collection("audit_logs").add(entry)
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
            query = self._db.collection("audit_logs").order_by("at", direction="DESCENDING")
            if actor:
                query = query.where("actor", "==", actor)
            if action:
                query = query.where("action", "==", action)
            if target:
                query = query.where("target", "==", target)
            docs = list(query.stream())
            total = len(docs)
            start = (page - 1) * limit
            result = []
            for doc in docs[start:start + limit]:
                d = doc.to_dict()
                d["log_id"] = doc.id
                result.append(d)
            return result, total
        return await self._run(_list)

    # ==========================================================================
    # ANNOUNCEMENTS
    # ==========================================================================

    async def list_announcements(self, active_only: bool = True) -> List[Dict[str, Any]]:
        def _list():
            query = self._db.collection("announcements").order_by("created_at", direction="DESCENDING")
            if active_only:
                query = query.where("active", "==", True)
            docs = query.stream()
            result = []
            for doc in docs:
                d = doc.to_dict()
                d["id"] = doc.id
                result.append(d)
            return result
        return await self._run(_list)

    async def create_announcement(self, data: Dict[str, Any]) -> str:
        def _create():
            _, ref = self._db.collection("announcements").add(data)
            return ref.id
        return await self._run(_create)

    async def update_announcement(self, ann_id: str, updates: Dict[str, Any]) -> None:
        def _update():
            self._db.collection("announcements").document(ann_id).update(updates)
        await self._run(_update)

    async def delete_announcement(self, ann_id: str) -> None:
        def _delete():
            self._db.collection("announcements").document(ann_id).delete()
        await self._run(_delete)

    # ==========================================================================
    # SETTINGS
    # ==========================================================================

    async def get_settings(self) -> Dict[str, Any]:
        def _get():
            doc = self._db.collection("settings").document("global").get()
            if not doc.exists:
                return dict(_DEFAULT_SETTINGS)
            return {**_DEFAULT_SETTINGS, **doc.to_dict()}
        return await self._run(_get)

    async def update_settings(self, updates: Dict[str, Any]) -> None:
        def _update():
            self._db.collection("settings").document("global").set(updates, merge=True)
        await self._run(_update)

    # ==========================================================================
    # STATS
    # ==========================================================================

    async def get_stats(self) -> Dict[str, Any]:
        def _get():
            users_count = len(list(self._db.collection("users").stream()))
            now = datetime.now(timezone.utc)
            all_licenses = list(self._db.collection("licenses").stream())
            unused = sum(1 for d in all_licenses if d.to_dict().get("status") == "unused")
            claimed = sum(1 for d in all_licenses if d.to_dict().get("status") == "claimed")
            banned = sum(1 for d in all_licenses if d.to_dict().get("status") == "banned")

            # Active subscriptions: users whose subscription.status == 'active'
            active_subs = 0
            expiring_soon = 0
            in_7_days = now + timedelta(days=7)
            for user_doc in self._db.collection("users").stream():
                sub = user_doc.to_dict().get("subscription", {})
                if sub.get("status") == "active":
                    active_subs += 1
                    exp = sub.get("expires_at")
                    if exp:
                        exp_dt = _ts_to_dt(exp)
                        if exp_dt and exp_dt <= in_7_days:
                            expiring_soon += 1
            return {
                "total_users": users_count,
                "active_subscriptions": active_subs,
                "expiring_soon_7d": expiring_soon,
                "licenses": {"unused": unused, "claimed": claimed, "banned": banned, "total": len(all_licenses)},
            }
        return await self._run(_get)


def _ts_to_dt(ts) -> Optional[datetime]:
    """Convert Firestore timestamp or datetime to timezone-aware datetime."""
    if ts is None:
        return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    # Firestore DatetimeWithNanoseconds has a timestamp() method
    if hasattr(ts, 'timestamp'):
        return datetime.fromtimestamp(ts.timestamp(), tz=timezone.utc)
    return None
