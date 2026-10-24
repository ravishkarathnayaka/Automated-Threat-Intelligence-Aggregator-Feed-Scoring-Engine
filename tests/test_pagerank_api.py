"""Integration tests for PageRank graph scoring API."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app


@pytest.mark.asyncio
async def test_pagerank_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "edges": [
                ["198.51.100.1", "c2-domain-1.com"],
                ["198.51.100.1", "c2-domain-2.com"],
                ["c2-domain-1.com", "hash-malware-xyz"],
            ],
            "damping": 0.85,
        }
        res = await client.post("/api/v1/scoring/pagerank", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["node_count"] == 4
        assert data["edge_count"] == 3
        assert "198.51.100.1" in data["rankings"]
        assert data["rankings"]["198.51.100.1"] == 1.0
