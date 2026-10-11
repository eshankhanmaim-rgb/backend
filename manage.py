#!/usr/bin/env python3
"""
Pruvate Auth Platform — Management CLI

Usage:
  python manage.py make_admin <username>
  python manage.py revoke_admin <username>
  python manage.py ban_user <username> [reason]
  python manage.py unban_user <username>
  python manage.py force_logout <username>
  python manage.py show_user <username>
"""
from __future__ import annotations
import sys
import json
import asyncio
from datetime import datetime, timezone


def _init_firebase():
    """Initialize Firebase and return the configured DatabaseAdapter."""
    from app.main import init_firebase_adapter
    return init_firebase_adapter()


async def make_admin(username: str):
    adapter = _init_firebase()
    user = await adapter.get_user_by_username(username)
    if not user:
        print(f"ERROR: User '{username}' not found.")
        sys.exit(1)
    await adapter.update_user(user["uid"], {"admin": True})
    print(f"SUCCESS: '{username}' (uid={user['uid']}) is now an admin.")
    print("NOTE: Admin status is enforced server-side from the database on every admin request.")


async def revoke_admin(username: str):
    adapter = _init_firebase()
    user = await adapter.get_user_by_username(username)
    if not user:
        print(f"ERROR: User '{username}' not found.")
        sys.exit(1)
    await adapter.update_user(user["uid"], {"admin": False})
    print(f"SUCCESS: Admin privileges revoked from '{username}'.")


async def ban_user(username: str, reason: str = ""):
    adapter = _init_firebase()
    user = await adapter.get_user_by_username(username)
    if not user:
        print(f"ERROR: User '{username}' not found.")
        sys.exit(1)
    await adapter.update_user(user["uid"], {"banned": True, "ban_reason": reason})
    await adapter.revoke_all_web_sessions(user["uid"])
    await adapter.revoke_user_loader_sessions(user["uid"])
    print(f"SUCCESS: '{username}' has been banned.")


async def unban_user(username: str):
    adapter = _init_firebase()
    user = await adapter.get_user_by_username(username)
    if not user:
        print(f"ERROR: User '{username}' not found.")
        sys.exit(1)
    await adapter.update_user(user["uid"], {"banned": False, "ban_reason": None})
    print(f"SUCCESS: '{username}' has been unbanned.")


async def force_logout(username: str):
    adapter = _init_firebase()
    user = await adapter.get_user_by_username(username)
    if not user:
        print(f"ERROR: User '{username}' not found.")
        sys.exit(1)
    current_version = user.get("token_version", 1)
    await adapter.update_user(user["uid"], {"token_version": current_version + 1})
    await adapter.revoke_all_web_sessions(user["uid"])
    await adapter.revoke_user_loader_sessions(user["uid"])
    print(f"SUCCESS: All sessions for '{username}' have been revoked.")


async def show_user(username: str):
    adapter = _init_firebase()
    user = await adapter.get_user_by_username(username)
    if not user:
        print(f"ERROR: User '{username}' not found.")
        sys.exit(1)
    # Scrub sensitive fields
    safe = {k: v for k, v in user.items() if k not in ("password_hash", "totp_secret_enc")}
    import pprint
    pprint.pprint(safe)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    commands = {
        "make_admin": (make_admin, 1),
        "revoke_admin": (revoke_admin, 1),
        "ban_user": (ban_user, 1),
        "unban_user": (unban_user, 1),
        "force_logout": (force_logout, 1),
        "show_user": (show_user, 1),
    }

    if cmd not in commands:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)

    fn, min_args = commands[cmd]
    if len(args) < min_args:
        print(f"Usage: python manage.py {cmd} <username>")
        sys.exit(1)

    asyncio.run(fn(*args))


if __name__ == "__main__":
    main()
