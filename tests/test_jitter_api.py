"""Integration test for C2 beacon jitter analysis API endpoint."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app


@pytest.mark.asyncio
async def test_jitter_analysis_strict_beacon():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "timestamps": [100.0, 160.0, 220.0, 280.0, 340.0]
        }
        res = await client.post("/api/v1/scoring/jitter-analysis", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["is_beacon"] is True
        assert data["classification"] == "strict_periodic_c2_beaconing"
        assert data["risk_penalty"] == 35.0


@pytest.mark.asyncio
async def test_jitter_analysis_sporadic():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "timestamps": [10.0, 15.0, 120.0, 122.0, 950.0]
        }
        res = await client.post("/api/v1/scoring/jitter-analysis", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["is_beacon"] is False
        assert data["classification"] == "normal_sporadic_network_traffic"
