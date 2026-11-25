"""Integration tests for v6 Cloud Gateway, WAF, and IAM Action export API endpoints."""

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
async def test_traefik_middleware_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/traefik-middleware.yaml?min_score=50")
        assert res.status_code == 200
        assert "kind: Middleware" in res.text
        assert "traefik.io/v1alpha1" in res.text
        assert "ipWhiteList" in res.text or "sourceRange" in res.text


@pytest.mark.asyncio
async def test_azure_front_door_waf_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/azure-front-door.json?min_score=50")
        assert res.status_code == 200
        data = res.json()
        assert "policySettings" in data or "customRules" in data
        assert "rules" in data["customRules"]
        assert len(data["customRules"]["rules"]) >= 1


@pytest.mark.asyncio
async def test_auth0_action_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/auth0-action.js?min_score=50")
        assert res.status_code == 200
        assert "exports.onExecutePostLogin" in res.text
        assert "api.access.deny" in res.text
