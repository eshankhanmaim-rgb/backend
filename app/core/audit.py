"""
Audit log writer. Every sensitive action writes an immutable audit entry.
"""
from typing import Optional, Any, Dict
from datetime import datetime, timezone
import structlog

log = structlog.get_logger()

# Will be set by main.py after the DB adapter is initialized
_db_adapter = None


def set_db_adapter(adapter) -> None:
    global _db_adapter
    _db_adapter = adapter


async def write_audit(
    action: str,
    actor: str = "system",
    target: Optional[str] = None,
    ip: str = "",
    meta: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Write an audit log entry.
    
    action examples: 'user.register', 'user.login', 'user.login_failed',
                     'license.redeem', 'hwid.reset', 'admin.ban_user',
                     'loader.login', 'loader.heartbeat_fail'
    """
    if meta is None:
        meta = {}
    
    # Never log passwords, tokens, or full keys in audit meta
    _scrub_secrets(meta)

    entry = {
        "actor": actor,
        "action": action,
        "target": target,
        "ip": ip,
        "meta": meta,
        "at": datetime.now(timezone.utc),
    }

    if _db_adapter is None:
        log.warning("audit_no_db", action=action, actor=actor, target=target)
        return

    try:
        await _db_adapter.create_audit_log(entry)
    except Exception as e:
        # Audit log failure must never crash the request
        log.error("audit_write_failed", action=action, error=str(e))


_SECRET_KEYS = {"password", "password_hash", "token", "key", "secret", "access_token", "refresh_token"}


def _scrub_secrets(d: Dict[str, Any]) -> None:
    """Remove secret-looking keys from a dict, in-place."""
    for k in list(d.keys()):
        if any(s in k.lower() for s in _SECRET_KEYS):
            d[k] = "[REDACTED]"
        elif isinstance(d[k], dict):
            _scrub_secrets(d[k])
