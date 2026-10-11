"""
Tests for license generation, redemption, banning, and HWID reset logic.
"""
import pytest
from httpx import AsyncClient
from typing import Dict
import asyncio

from tests.conftest import auth_headers_for

pytestmark = pytest.mark.asyncio

class TestLicensesAndAdmin:
    
    async def test_key_generation_admin_only(self, client: AsyncClient, verified_user: Dict, admin_user: Dict):
        user_headers = auth_headers_for(verified_user)
        admin_headers = auth_headers_for(admin_user)
        
        # Non-admin
        resp = await client.post("/api/v1/admin/licenses/generate", json={
            "prefix": "TEST",
            "quantity": 1,
            "duration_days": 30
        }, headers=user_headers)
        assert resp.status_code == 403
        
        # Admin
        resp = await client.post("/api/v1/admin/licenses/generate", json={
            "prefix": "TEST",
            "quantity": 2,
            "duration_days": 30
        }, headers=admin_headers)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["ok"] is True
        assert data["count"] == 2
        assert len(data["keys"]) == 2
        assert data["keys"][0].startswith("TEST-")
        
    async def test_single_redeem_grants_subscription(self, client: AsyncClient, verified_user: Dict, admin_user: Dict):
        admin_headers = auth_headers_for(admin_user)
        user_headers = auth_headers_for(verified_user)
        
        # Generate
        resp = await client.post("/api/v1/admin/licenses/generate", json={
            "prefix": "SUB",
            "quantity": 1,
            "duration_days": 30
        }, headers=admin_headers)
        key = resp.json()["keys"][0]
        
        # Redeem
        resp = await client.post("/api/v1/license/redeem", json={"key": key}, headers=user_headers)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["ok"] is True
        assert data["days_added"] == 30
        assert data["lifetime"] is False
        
        # Check sub
        resp = await client.get("/api/v1/subscription", headers=user_headers)
        assert resp.status_code == 200
        sub = resp.json()["subscription"]
        assert sub["status"] == "active"
        assert sub["days_left"] in [29, 30]

    async def test_simultaneous_double_redeem(self, client: AsyncClient, verified_user: Dict, admin_user: Dict):
        admin_headers = auth_headers_for(admin_user)
        user_headers = auth_headers_for(verified_user)
        
        # Generate 1 key
        resp = await client.post("/api/v1/admin/licenses/generate", json={
            "prefix": "RACE",
            "quantity": 1,
            "duration_days": 10
        }, headers=admin_headers)
        key = resp.json()["keys"][0]
        
        # Race condition
        reqs = [
            client.post("/api/v1/license/redeem", json={"key": key}, headers=user_headers),
            client.post("/api/v1/license/redeem", json={"key": key}, headers=user_headers)
        ]
        results = await asyncio.gather(*reqs)
        
        status_codes = [r.status_code for r in results]
        assert 200 in status_codes
        assert 409 in status_codes
        
    async def test_banning_license_recalculates_subscription(self, client: AsyncClient, db, verified_user: Dict, admin_user: Dict):
        admin_headers = auth_headers_for(admin_user)
        user_headers = auth_headers_for(verified_user)
        
        # Generate
        resp = await client.post("/api/v1/admin/licenses/generate", json={
            "prefix": "BAN",
            "quantity": 1,
            "duration_days": 30
        }, headers=admin_headers)
        key = resp.json()["keys"][0]
        
        # Redeem
        resp = await client.post("/api/v1/license/redeem", json={"key": key}, headers=user_headers)
        assert resp.status_code == 200
        
        # Find license ID
        resp = await client.get("/api/v1/admin/licenses", headers=admin_headers)
        licenses = resp.json()["items"]
        license_id = next(l["id"] for l in licenses if l["prefix"] == "BAN")
        
        # Ban license
        resp = await client.post(f"/api/v1/admin/licenses/{license_id}/ban", json={"reason": "test"}, headers=admin_headers)
        assert resp.status_code == 200
        
        # Check sub
        resp = await client.get("/api/v1/subscription", headers=user_headers)
        assert resp.status_code == 200
        sub = resp.json()["subscription"]
        assert sub["status"] == "disabled"
        
    async def test_user_hwid_reset_and_admin(self, client: AsyncClient, db, verified_user: Dict, admin_user: Dict):
        user_headers = auth_headers_for(verified_user)
        admin_headers = auth_headers_for(admin_user)
        
        # User resets HWID
        resp = await client.post("/api/v1/hwid/reset", json={
            "username": verified_user["username"],
            "password": "TestPassword123"
        }, headers=user_headers)
        assert resp.status_code == 200, resp.text
        
        # User tries again immediately (cooldown)
        resp = await client.post("/api/v1/hwid/reset", json={
            "username": verified_user["username"],
            "password": "TestPassword123"
        }, headers=user_headers)
        assert resp.status_code == 429
        assert "cooldown" in resp.text.lower()
        
        # Admin reset works regardless
        uid = verified_user["uid"]
        resp = await client.post(f"/api/v1/admin/users/{uid}/hwid-reset", headers=admin_headers)
        assert resp.status_code == 200
        
    async def test_non_admin_routes(self, client: AsyncClient, verified_user: Dict):
        user_headers = auth_headers_for(verified_user)
        
        resp = await client.get("/api/v1/admin/users", headers=user_headers)
        assert resp.status_code == 403
        
        resp = await client.get("/api/v1/admin/stats", headers=user_headers)
        assert resp.status_code == 403

    async def test_dual_product_licensing_and_loader_detection(self, client: AsyncClient, db, verified_user: Dict, admin_user: Dict):
        import time
        from app.core.config import get_settings
        from app.core.crypto import generate_x25519_keypair

        admin_headers = auth_headers_for(admin_user)
        user_headers = auth_headers_for(verified_user)

        # 1. Admin creates two products
        r1 = await client.post("/api/v1/admin/products", json={
            "product_id": "cs2_pro",
            "name": "Pruvate CS2 Pro",
            "description": "CS2 Kernel Build"
        }, headers=admin_headers)
        assert r1.status_code == 201

        r2 = await client.post("/api/v1/admin/products", json={
            "product_id": "val_lite",
            "name": "Pruvate Valorant Lite",
            "description": "Val External Build"
        }, headers=admin_headers)
        assert r2.status_code == 201

        # 2. Admin generates 1 key for each product
        k1_resp = await client.post("/api/v1/admin/licenses/generate", json={
            "prefix": "CS2",
            "quantity": 1,
            "duration_days": 30,
            "product_id": "cs2_pro"
        }, headers=admin_headers)
        key_cs2 = k1_resp.json()["keys"][0]

        k2_resp = await client.post("/api/v1/admin/licenses/generate", json={
            "prefix": "VAL",
            "quantity": 1,
            "duration_days": 14,
            "product_id": "val_lite"
        }, headers=admin_headers)
        key_val = k2_resp.json()["keys"][0]

        # 3. User redeems both keys (dual-product unlock)
        red1 = await client.post("/api/v1/license/redeem", json={"key": key_cs2}, headers=user_headers)
        assert red1.status_code == 200
        assert red1.json()["product_id"] == "cs2_pro"
        assert red1.json()["product_name"] == "Pruvate CS2 Pro"

        red2 = await client.post("/api/v1/license/redeem", json={"key": key_val}, headers=user_headers)
        assert red2.status_code == 200
        assert red2.json()["product_id"] == "val_lite"
        assert red2.json()["product_name"] == "Pruvate Valorant Lite"

        # 4. Dashboard /subscription returns BOTH unlocked products
        sub_resp = await client.get("/api/v1/subscription", headers=user_headers)
        assert sub_resp.status_code == 200
        subs = sub_resp.json()["subscriptions"]
        unlocked_ids = {s["product_id"]: s["product_name"] for s in subs if s["status"] == "active"}
        assert unlocked_ids.get("cs2_pro") == "Pruvate CS2 Pro"
        assert unlocked_ids.get("val_lite") == "Pruvate Valorant Lite"

        # 5. Loader login succeeds for cs2_pro and val_lite, fails for apex_pro
        s = get_settings()
        _, pub1 = generate_x25519_keypair()
        l_cs2 = await client.post("/api/v1/loader/login", json={
            "app_id": s.loader_app_id,
            "build": s.min_loader_version,
            "product_id": "cs2_pro",
            "identifier": verified_user["username"],
            "password": "TestPassword123",
            "hwid": {"combined_hash": "hwid_dual", "components": ["hwid_dual"]},
            "client_nonce": "nonce_dual_cs2",
            "client_ephemeral_pub": pub1.hex(),
            "ts": int(time.time()),
        })
        assert l_cs2.status_code == 200
        assert l_cs2.json()["subscription"]["product_id"] == "cs2_pro"
        assert l_cs2.json()["subscription"]["product_name"] == "Pruvate CS2 Pro"

        _, pub2 = generate_x25519_keypair()
        l_apex = await client.post("/api/v1/loader/login", json={
            "app_id": s.loader_app_id,
            "build": s.min_loader_version,
            "product_id": "apex_pro",
            "identifier": verified_user["username"],
            "password": "TestPassword123",
            "hwid": {"combined_hash": "hwid_dual", "components": ["hwid_dual"]},
            "client_nonce": "nonce_dual_apex",
            "client_ephemeral_pub": pub2.hex(),
            "ts": int(time.time()),
        })
        assert l_apex.status_code == 403
        assert l_apex.json()["code"] == "NO_SUBSCRIPTION"

    async def test_marketplace_crud(self, client: AsyncClient, verified_user: Dict):
        user_headers = auth_headers_for(verified_user)

        # Create script
        c_resp = await client.post("/api/v1/scripts", json={
            "title": "Legit Aimbot Helper",
            "description": "Smooth FOV helper for CS2",
            "code": "function on_tick() print('tick') end",
            "tags": ["legit", "combat"],
            "product_id": "cs2_pro"
        }, headers=user_headers)
        assert c_resp.status_code == 201
        script_id = c_resp.json()["script"]["id"]

        # List scripts
        l_resp = await client.get("/api/v1/scripts")
        assert l_resp.status_code == 200
        assert any(s["id"] == script_id for s in l_resp.json()["items"])

        # Like & download
        like_resp = await client.post(f"/api/v1/scripts/{script_id}/like", headers=user_headers)
        assert like_resp.status_code == 200
        assert like_resp.json()["likes"] == 1

        dl_resp = await client.post(f"/api/v1/scripts/{script_id}/download")
        assert dl_resp.status_code == 200
        assert dl_resp.json()["downloads"] == 1

