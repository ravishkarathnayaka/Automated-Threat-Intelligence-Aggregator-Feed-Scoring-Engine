"""Integration tests for v4 cloud-native service mesh and zero trust export API endpoints."""

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
async def test_istio_policy_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/istio-policy.yaml?min_score=50")
        assert res.status_code == 200
        assert "text/yaml" in res.headers["content-type"]
        assert "kind: AuthorizationPolicy" in res.text
        assert "action: DENY" in res.text


@pytest.mark.asyncio
async def test_cilium_policy_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/cilium-policy.yaml?min_score=50")
        assert res.status_code == 200
        assert "text/yaml" in res.headers["content-type"]
        assert "kind: CiliumNetworkPolicy" in res.text
        assert "egressDeny:" in res.text
