import pytest
import time
import json
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
import nacl.public
from app.core.config import get_settings
from app.core.crypto import verify_signature, generate_x25519_keypair, derive_session_key
from tests.conftest import InMemoryAdapter

pytestmark = pytest.mark.asyncio

class TestLoader:
    async def test_loader_status(self, client: AsyncClient):
        # request
        s = get_settings()
        resp = await client.get("/api/v1/loader/status", headers={"X-App-Id": s.loader_app_id})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["version"] == s.current_loader_version
        
        sig = resp.headers.get("x-signature")
        assert sig
        assert verify_signature(resp.content, sig)

    async def test_loader_login_success(self, client: AsyncClient, db: InMemoryAdapter, verified_user: dict):
        s = get_settings()
        await db.update_user(verified_user["uid"], {
            "subscription": {"status": "active", "expires_at": datetime.now(timezone.utc) + timedelta(days=30)}
        })
        
        client_priv, client_pub = generate_x25519_keypair()
        
        payload = {
            "app_id": s.loader_app_id,
            "build": s.min_loader_version,
            "identifier": verified_user["username"],
            "password": "TestPassword123",
            "hwid": {
                "combined_hash": "hash123",
                "components": ["cpu_1", "mb_2"]
            },
            "client_nonce": "nonce_123",
            "client_ephemeral_pub": client_pub.hex(),
            "ts": int(time.time())
        }
        
        resp = await client.post("/api/v1/loader/login", json=payload)
        assert resp.status_code == 200
        
        sig = resp.headers.get("x-signature")
        assert sig
        assert verify_signature(resp.content, sig)
        
        data = resp.json()
        assert data["ok"] is True
        assert data["client_nonce"] == "nonce_123"
        assert "session_token" in data
        
    async def test_loader_login_replay(self, client: AsyncClient, db: InMemoryAdapter, verified_user: dict):
        s = get_settings()
        await db.update_user(verified_user["uid"], {
            "subscription": {"status": "active", "expires_at": datetime.now(timezone.utc) + timedelta(days=30)}
        })
        client_priv, client_pub = generate_x25519_keypair()
        payload = {
            "app_id": s.loader_app_id,
            "build": s.min_loader_version,
            "identifier": verified_user["username"],
            "password": "TestPassword123",
            "hwid": {
                "combined_hash": "hash123",
                "components": ["cpu_1", "mb_2"]
            },
            "client_nonce": "nonce_123_replay",
            "client_ephemeral_pub": client_pub.hex(),
            "ts": int(time.time())
        }
        resp = await client.post("/api/v1/loader/login", json=payload)
        assert resp.status_code == 200
        
        resp2 = await client.post("/api/v1/loader/login", json=payload)
        assert resp2.status_code == 400
        assert resp2.json()["code"] == "REPLAY_ATTACK"

    async def test_loader_heartbeat_success(self, client: AsyncClient, db: InMemoryAdapter, verified_user: dict):
        # login first
        s = get_settings()
        await db.update_user(verified_user["uid"], {
            "subscription": {"status": "active", "expires_at": datetime.now(timezone.utc) + timedelta(days=30)}
        })
        client_priv, client_pub = generate_x25519_keypair()
        payload = {
            "app_id": s.loader_app_id,
            "build": s.min_loader_version,
            "identifier": verified_user["username"],
            "password": "TestPassword123",
            "hwid": {
                "combined_hash": "hash123",
                "components": ["cpu_1", "mb_2"]
            },
            "client_nonce": "nonce_heartbeat",
            "client_ephemeral_pub": client_pub.hex(),
            "ts": int(time.time())
        }
        resp = await client.post("/api/v1/loader/login", json=payload)
        session_token = resp.json()["session_token"]
        
        hb_payload = {
            "session_token": session_token,
            "seq": 1,
            "nonce": "hb_nonce_1",
            "ts": int(time.time()),
            "mac": "dummy"
        }
        
        hb_resp = await client.post("/api/v1/loader/heartbeat", json=hb_payload)
        assert hb_resp.status_code == 200
        assert verify_signature(hb_resp.content, hb_resp.headers.get("x-signature"))
        hb_data = hb_resp.json()
        assert hb_data["directive"] == "none"

    async def test_loader_heartbeat_banned(self, client: AsyncClient, db: InMemoryAdapter, verified_user: dict):
        s = get_settings()
        await db.update_user(verified_user["uid"], {
            "subscription": {"status": "active", "expires_at": datetime.now(timezone.utc) + timedelta(days=30)}
        })
        client_priv, client_pub = generate_x25519_keypair()
        payload = {
            "app_id": s.loader_app_id,
            "build": s.min_loader_version,
            "identifier": verified_user["username"],
            "password": "TestPassword123",
            "hwid": {
                "combined_hash": "hash123",
                "components": ["cpu_1", "mb_2"]
            },
            "client_nonce": "nonce_banned",
            "client_ephemeral_pub": client_pub.hex(),
            "ts": int(time.time())
        }
        resp = await client.post("/api/v1/loader/login", json=payload)
        session_token = resp.json()["session_token"]
        
        # ban user
        await db.update_user(verified_user["uid"], {"banned": True, "ban_reason": "banned for test"})
        
        hb_payload = {
            "session_token": session_token,
            "seq": 1,
            "nonce": "hb_nonce_2",
            "ts": int(time.time()),
            "mac": "dummy"
        }
        
        hb_resp = await client.post("/api/v1/loader/heartbeat", json=hb_payload)
        assert hb_resp.status_code == 200
        hb_data = hb_resp.json()
        assert hb_data["directive"] == "terminate"

    async def test_loader_heartbeat_out_of_order(self, client: AsyncClient, db: InMemoryAdapter, verified_user: dict):
        s = get_settings()
        await db.update_user(verified_user["uid"], {
            "subscription": {"status": "active", "expires_at": datetime.now(timezone.utc) + timedelta(days=30)}
        })
        client_priv, client_pub = generate_x25519_keypair()
        payload = {
            "app_id": s.loader_app_id,
            "build": s.min_loader_version,
            "identifier": verified_user["username"],
            "password": "TestPassword123",
            "hwid": {
                "combined_hash": "hash123",
                "components": ["cpu_1", "mb_2"]
            },
            "client_nonce": "nonce_order",
            "client_ephemeral_pub": client_pub.hex(),
            "ts": int(time.time())
        }
        resp = await client.post("/api/v1/loader/login", json=payload)
        session_token = resp.json()["session_token"]
        
        hb_payload = {
            "session_token": session_token,
            "seq": 2,
            "nonce": "hb_nonce_seq_1",
            "ts": int(time.time()),
            "mac": "dummy"
        }
        await client.post("/api/v1/loader/heartbeat", json=hb_payload)
        
        # Out of order
        hb_payload2 = {
            "session_token": session_token,
            "seq": 1,
            "nonce": "hb_nonce_seq_2",
            "ts": int(time.time()),
            "mac": "dummy"
        }
        
        hb_resp2 = await client.post("/api/v1/loader/heartbeat", json=hb_payload2)
        assert hb_resp2.status_code == 401

    async def test_loader_logout(self, client: AsyncClient, db: InMemoryAdapter, verified_user: dict):
        s = get_settings()
        await db.update_user(verified_user["uid"], {
            "subscription": {"status": "active", "expires_at": datetime.now(timezone.utc) + timedelta(days=30)}
        })
        client_priv, client_pub = generate_x25519_keypair()
        payload = {
            "app_id": s.loader_app_id,
            "build": s.min_loader_version,
            "identifier": verified_user["username"],
            "password": "TestPassword123",
            "hwid": {
                "combined_hash": "hash123",
                "components": ["cpu_1", "mb_2"]
            },
            "client_nonce": "nonce_logout",
            "client_ephemeral_pub": client_pub.hex(),
            "ts": int(time.time())
        }
        resp = await client.post("/api/v1/loader/login", json=payload)
        session_token = resp.json()["session_token"]
        
        logout_payload = {
            "session_token": session_token
        }
        logout_resp = await client.post("/api/v1/loader/logout", json=logout_payload)
        assert logout_resp.status_code == 200
        
        # Check heartbeat fails
        hb_payload = {
            "session_token": session_token,
            "seq": 1,
            "nonce": "hb_nonce_after_logout",
            "ts": int(time.time()),
            "mac": "dummy"
        }
        hb_resp = await client.post("/api/v1/loader/heartbeat", json=hb_payload)
        assert hb_resp.status_code == 401
