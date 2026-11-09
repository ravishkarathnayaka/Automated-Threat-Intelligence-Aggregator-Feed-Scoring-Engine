"""Integration tests for v5 stochastic scoring API endpoints (Dempster-Shafer, Hawkes, Wasserstein)."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app


@pytest.mark.asyncio
async def test_dempster_shafer_scoring_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "masses": [
                {"malicious": 0.75, "benign": 0.05, "uncertain": 0.20},
                {"malicious": 0.85, "benign": 0.05, "uncertain": 0.10},
            ]
        }
        res = await client.post("/api/v1/scoring/dempster-shafer", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["belief_malicious"] > 0.85
        assert data["composite_score"] > 85.0


@pytest.mark.asyncio
async def test_hawkes_intensity_scoring_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "timestamps": [9.1, 9.4, 9.6, 9.8, 10.0],
            "evaluation_time": 10.0,
        }
        res = await client.post("/api/v1/scoring/hawkes-intensity", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["intensity_lambda"] > 2.5
        assert data["risk_boost"] > 15.0


@pytest.mark.asyncio
async def test_wasserstein_drift_scoring_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "baseline_scores": [60.0, 62.0, 65.0, 68.0],
            "current_scores": [90.0, 92.0, 95.0, 98.0],
        }
        res = await client.post("/api/v1/scoring/wasserstein-drift", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["is_drifted"] is True
        assert data["w1_distance"] >= 25.0
