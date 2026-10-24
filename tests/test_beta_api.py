"""Integration tests for Beta-Binomial Bayesian scoring API."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app


@pytest.mark.asyncio
async def test_beta_scoring_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "malicious_count": 8,
            "benign_count": 1,
            "prior_alpha": 1.0,
            "prior_beta": 4.0,
        }
        res = await client.post("/api/v1/scoring/beta-distribution", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["alpha"] == 9.0
        assert data["beta"] == 5.0
        assert 0.60 < data["posterior_probability"] < 0.70
        assert data["confidence_score"] > 60.0
        assert "epistemic_variance" in data
