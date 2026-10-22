"""Integration tests for mathematical scoring simulation API."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app


@pytest.mark.asyncio
async def test_scoring_simulation_default():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "initial_score": 85.0,
            "ioc_type": "ipv4",
            "age_days": 5.0,
            "measurements": [80.0, 85.0, 90.0],
            "current_state": "active",
        }
        res = await client.post("/api/v1/scoring/simulate", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "weibull_decayed_score" in data
        assert "weibull_survival_prob" in data
        assert "kalman_filtered_score" in data
        assert "markov_next_probabilities" in data
        assert data["weibull_survival_prob"] <= 1.0
        assert data["kalman_filtered_score"] > 0
        assert "active" in data["markov_next_probabilities"]


@pytest.mark.asyncio
async def test_scoring_simulation_domain_dormant():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "initial_score": 95.0,
            "ioc_type": "domain",
            "age_days": 12.0,
            "measurements": [90.0, 92.0],
            "current_state": "dormant",
        }
        res = await client.post("/api/v1/scoring/simulate", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["markov_next_probabilities"]["dormant"] > 0.5
        assert data["weibull_decayed_score"] <= 95.0
