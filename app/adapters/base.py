"""
Abstract database adapter interface.
Swap FirestoreAdapter for any other implementation without touching routes.
"""
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime


class DatabaseAdapter(ABC):
    """Abstract interface for all database operations."""

    # --- Users ---
    @abstractmethod
    async def get_user_by_uid(self, uid: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    async def get_user_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Look up by username OR email (case-insensitive)."""
        ...

    @abstractmethod
    async def create_user(
        self,
        uid: str,
        username: str,
        email: str,
        password_hash: str,
    ) -> Dict[str, Any]:
        """Atomically creates user + username index + email index."""
        ...

    @abstractmethod
    async def update_user(self, uid: str, updates: Dict[str, Any]) -> None: ...

    @abstractmethod
    async def list_users(
        self,
        search: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]: ...

    # --- Web Sessions (refresh tokens) ---
    @abstractmethod
    async def create_web_session(
        self,
        uid: str,
        token_hash: str,
        ip: str,
        user_agent: str,
        family_id: str,
    ) -> str:
        """Returns session_id."""
        ...

    @abstractmethod
    async def get_web_session_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    async def rotate_web_session(
        self,
        session_id: str,
        new_token_hash: str,
        ip: str,
    ) -> None: ...

    @abstractmethod
    async def revoke_web_session(self, session_id: str) -> None: ...

    @abstractmethod
    async def revoke_all_web_sessions(self, uid: str) -> None: ...

    @abstractmethod
    async def detect_refresh_token_reuse(
        self,
        family_id: str,
        token_hash: str,
    ) -> bool:
        """Returns True if the family was already consumed by a different token (reuse attack)."""
        ...

    @abstractmethod
    async def list_web_sessions(self, uid: str) -> List[Dict[str, Any]]: ...

    # --- Email verification / password reset tokens ---
    @abstractmethod
    async def store_token(
        self,
        token_type: str,
        uid: str,
        token_hash: str,
        expires_at: datetime,
        extra: Optional[Dict] = None,
    ) -> None: ...

    @abstractmethod
    async def consume_token(
        self,
        token_type: str,
        token_hash: str,
    ) -> Optional[Dict[str, Any]]:
        """Returns token doc and deletes it atomically. Returns None if not found/expired."""
        ...

    # --- Nonces (replay prevention) ---
    @abstractmethod
    async def check_and_store_nonce(self, nonce: str, ttl_seconds: int) -> bool:
        """Returns True if nonce is new (and stores it). Returns False if already seen."""
        ...

    # --- Licenses ---
    @abstractmethod
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
    ) -> Dict[str, Any]: ...

    @abstractmethod
    async def get_license_by_lookup(self, key_lookup: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    async def get_license_by_id(self, license_id: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    async def claim_license_atomic(
        self,
        license_id: str,
        uid: str,
        starts_at: datetime,
        ends_at: Optional[datetime],
    ) -> bool:
        """Atomically claim a license. Returns True if this caller won the race."""
        ...

    @abstractmethod
    async def update_license(self, license_id: str, updates: Dict[str, Any]) -> None: ...

    @abstractmethod
    async def list_licenses(
        self,
        search: Optional[str] = None,
        status: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]: ...

    @abstractmethod
    async def get_user_active_licenses(self, uid: str) -> List[Dict[str, Any]]:
        """Returns all non-banned, non-deleted licenses claimed by this user."""
        ...

    # --- Loader Sessions ---
    @abstractmethod
    async def create_loader_session(
        self,
        session_id: str,
        uid: str,
        token_hash: str,
        hwid_hash: str,
        ip: str,
        app_version: str,
        expires_at: datetime,
    ) -> None: ...

    @abstractmethod
    async def get_loader_session_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    async def update_loader_session(self, session_id: str, updates: Dict[str, Any]) -> None: ...

    @abstractmethod
    async def revoke_loader_session(self, session_id: str) -> None: ...

    @abstractmethod
    async def revoke_user_loader_sessions(self, uid: str) -> None: ...

    @abstractmethod
    async def count_active_loader_sessions(self, uid: str) -> int: ...

    @abstractmethod
    async def get_oldest_loader_session(self, uid: str) -> Optional[Dict[str, Any]]: ...

    # --- Scripts ---
    @abstractmethod
    async def create_script(self, script_data: Dict[str, Any]) -> str:
        """Returns script_id."""
        ...

    @abstractmethod
    async def get_script(self, script_id: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    async def update_script(self, script_id: str, updates: Dict[str, Any]) -> None: ...

    @abstractmethod
    async def list_scripts(
        self,
        search: Optional[str] = None,
        tag: Optional[str] = None,
        sort: str = "new",
        status: str = "published",
        page: int = 1,
        limit: int = 24,
    ) -> Tuple[List[Dict[str, Any]], int]: ...

    # --- Releases ---
    @abstractmethod
    async def create_release(self, release_data: Dict[str, Any]) -> None: ...

    @abstractmethod
    async def get_active_release(self) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    async def list_releases(self) -> List[Dict[str, Any]]: ...

    @abstractmethod
    async def update_release(self, version: str, updates: Dict[str, Any]) -> None: ...

    # --- API Keys ---
    @abstractmethod
    async def create_api_key(self, key_data: Dict[str, Any]) -> str:
        """Returns key_id."""
        ...

    @abstractmethod
    async def get_api_key_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    async def list_api_keys(self) -> List[Dict[str, Any]]: ...

    @abstractmethod
    async def update_api_key(self, key_id: str, updates: Dict[str, Any]) -> None: ...

    # --- Audit Log ---
    @abstractmethod
    async def create_audit_log(self, entry: Dict[str, Any]) -> None: ...

    @abstractmethod
    async def list_audit_logs(
        self,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        target: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]: ...

    # --- Announcements ---
    @abstractmethod
    async def list_announcements(self, active_only: bool = True) -> List[Dict[str, Any]]: ...

    @abstractmethod
    async def create_announcement(self, data: Dict[str, Any]) -> str: ...

    @abstractmethod
    async def update_announcement(self, ann_id: str, updates: Dict[str, Any]) -> None: ...

    @abstractmethod
    async def delete_announcement(self, ann_id: str) -> None: ...

    # --- Settings ---
    @abstractmethod
    async def get_settings(self) -> Dict[str, Any]: ...

    @abstractmethod
    async def update_settings(self, updates: Dict[str, Any]) -> None: ...

    # --- Stats ---
    @abstractmethod
    async def get_stats(self) -> Dict[str, Any]: ...

    # --- Products ---
    async def create_product(
        self,
        product_id: str,
        name: str,
        description: str = "",
        status: str = "active",
    ) -> Dict[str, Any]:
        raise NotImplementedError

    async def get_product(self, product_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    async def list_products(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    async def delete_product(self, product_id: str) -> None:
        raise NotImplementedError

