"""Integration test for Dirichlet-Multinomial Bayesian scoring API endpoint."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app


@pytest.mark.asyncio
async def test_dirichlet_scoring_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "observations": {
                "c2": 40,
                "malware": 10,
                "benign": 0,
            }
        }
        res = await client.post("/api/v1/scoring/dirichlet", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["dominant_category"] == "c2"
        assert data["probabilities"]["c2"] > 0.60
        assert data["composite_threat_score"] > 80.0
        assert "variances" in data
        assert "entropy" in data
