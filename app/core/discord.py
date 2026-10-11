"""
Discord webhook sender for admin event notifications.
"""
from typing import Optional, Dict, Any, List
import httpx
import structlog
from datetime import datetime, timezone

from app.core.config import get_settings

log = structlog.get_logger()


async def _send_webhook(url: str, payload: Dict[str, Any]) -> bool:
    if not url:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload)
            return resp.status_code in (200, 204)
    except Exception as e:
        log.error("discord_webhook_failed", url=url[:40], error=str(e))
        return False


def _embed(
    title: str,
    description: str,
    color: int,
    fields: Optional[List[Dict]] = None,
) -> Dict:
    embed: Dict[str, Any] = {
        "title": title,
        "description": description,
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if fields:
        embed["fields"] = fields
    return embed


async def notify_key_generated(
    admin_username: str,
    count: int,
    prefix: str,
    duration_label: str,
) -> None:
    s = get_settings()
    payload = {
        "embeds": [_embed(
            title="🔑 License Keys Generated",
            description=f"**{admin_username}** generated **{count}** key(s)",
            color=0x3b82f6,
            fields=[
                {"name": "Prefix", "value": prefix or "(default)", "inline": True},
                {"name": "Duration", "value": duration_label, "inline": True},
            ],
        )]
    }
    await _send_webhook(s.discord_webhook_keys, payload)


async def notify_key_claimed(
    username: str,
    prefix: str,
    duration_label: str,
    discord_id: Optional[str],
    ip: str,
) -> None:
    s = get_settings()
    fields = [
        {"name": "Key Prefix", "value": prefix, "inline": True},
        {"name": "Duration", "value": duration_label, "inline": True},
        {"name": "IP", "value": ip, "inline": True},
    ]
    if discord_id:
        fields.append({"name": "Discord ID", "value": discord_id, "inline": True})
    payload = {
        "embeds": [_embed(
            title="✅ License Key Claimed",
            description=f"**{username}** redeemed a key",
            color=0x22c55e,
            fields=fields,
        )]
    }
    await _send_webhook(s.discord_webhook_keys, payload)


async def notify_ban(
    target_username: str,
    actor_username: str,
    reason: str,
    target_type: str = "user",
) -> None:
    s = get_settings()
    payload = {
        "embeds": [_embed(
            title=f"🔨 {target_type.capitalize()} Banned",
            description=f"**{actor_username}** banned **{target_username}**",
            color=0xef4444,
            fields=[{"name": "Reason", "value": reason or "No reason provided", "inline": False}],
        )]
    }
    await _send_webhook(s.discord_webhook_admin, payload)


async def notify_hwid_reset(
    target_username: str,
    actor_username: str,
    actor_is_admin: bool,
    ip: str,
) -> None:
    s = get_settings()
    payload = {
        "embeds": [_embed(
            title="🔄 HWID Reset",
            description=f"HWID reset for **{target_username}** by **{actor_username}**"
                        + (" (admin)" if actor_is_admin else ""),
            color=0xf59e0b,
            fields=[{"name": "IP", "value": ip, "inline": True}],
        )]
    }
    await _send_webhook(s.discord_webhook_admin, payload)


async def notify_suspicious_login(
    username: str,
    reason: str,
    ip: str,
    hwid_hash: Optional[str] = None,
) -> None:
    s = get_settings()
    fields = [
        {"name": "Reason", "value": reason, "inline": False},
        {"name": "IP", "value": ip, "inline": True},
    ]
    if hwid_hash:
        fields.append({"name": "HWID (hash prefix)", "value": hwid_hash[:16] + "...", "inline": True})
    payload = {
        "embeds": [_embed(
            title="⚠️ Suspicious Activity",
            description=f"Suspicious event for **{username}**",
            color=0xf97316,
            fields=fields,
        )]
    }
    await _send_webhook(s.discord_webhook_security, payload)
