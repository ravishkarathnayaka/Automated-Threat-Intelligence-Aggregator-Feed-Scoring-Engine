"""Unit test for indicator taxonomy summary API endpoint."""

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
async def test_types_summary_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/indicators/types/summary")
        assert res.status_code == 200
        data = res.json()
        assert "summary" in data
        summary = data["summary"]
        assert isinstance(summary, dict)
        for ioc_type, details in summary.items():
            assert "total" in details
            assert "active" in details
            assert "whitelisted" in details
            assert "avg_confidence" in details
            assert "max_confidence" in details
            assert details["total"] >= details["active"]
