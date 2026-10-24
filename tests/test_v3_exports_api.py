"""Integration tests for v3 enterprise network security and cloud export API endpoints."""

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
async def test_cisco_firepower_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/cisco-firepower.json?min_score=50")
        assert res.status_code == 200
        assert "application/json" in res.headers["content-type"]
        data = res.json()
        assert "networkObjects" in data
        assert data["generator"] == "SENTINEL-CTI-Engine"


@pytest.mark.asyncio
async def test_juniper_srx_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/juniper-srx.set?min_score=50")
        assert res.status_code == 200
        assert "text/plain" in res.headers["content-type"]
        assert "set security zones security-zone untrust address-book" in res.text


@pytest.mark.asyncio
async def test_k8s_policy_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/k8s-policy.yaml?min_score=50")
        assert res.status_code == 200
        assert "kind: NetworkPolicy" in res.text
        assert "policyTypes:" in res.text


