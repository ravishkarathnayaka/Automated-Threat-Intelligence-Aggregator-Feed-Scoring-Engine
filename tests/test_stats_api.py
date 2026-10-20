"""Unit tests for CTI engine statistics endpoint."""

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
async def test_stats_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/stats")
        assert res.status_code == 200
        data = res.json()
        assert "total_indicators" in data
        assert "whitelisted_indicators" in data
        assert "active_threat_indicators" in data
        assert "average_confidence_score" in data
        assert "indicators_by_type" in data
        assert "indicators_by_severity" in data

        assert data["total_indicators"] >= 0
        assert isinstance(data["indicators_by_type"], dict)
        assert isinstance(data["indicators_by_severity"], dict)
