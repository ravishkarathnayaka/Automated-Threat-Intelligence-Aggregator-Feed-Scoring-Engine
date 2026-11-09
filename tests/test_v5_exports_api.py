"""Integration tests for v5 SASE, Cloud WAF, and Calico CNI export API endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app
from cti_core.database import AsyncSessionLocal, init_db
from cti_core.pipeline import global_pipeline


@pytest.fixture(scope="module", autouse=True)
async def setup_test_db():
    await init_db()
    async with AsyncSessionLocal() as session:
        await global_pipeline.run_pipeline(session, use_live=False, skip_enrichment=True)


@pytest.mark.asyncio
async def test_netskope_casb_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/netskope-casb.json?min_score=50")
        assert res.status_code == 200
        data = res.json()
        assert "data" in data
        assert "urls" in data["data"]


@pytest.mark.asyncio
async def test_zscaler_zia_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/zscaler-zia.json?min_score=50")
        assert res.status_code == 200
        data = res.json()
        assert data["customCategory"] is True
        assert "urls" in data


@pytest.mark.asyncio
async def test_google_cloud_armor_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/cloud-armor.json?min_score=50")
        assert res.status_code == 200
        data = res.json()
        assert data["type"] == "CLOUD_ARMOR"
        assert len(data["rules"]) >= 1


@pytest.mark.asyncio
async def test_calico_policy_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/calico-policy.yaml?min_score=50")
        assert res.status_code == 200
        assert "kind: GlobalNetworkPolicy" in res.text
        assert "action: Deny" in res.text
