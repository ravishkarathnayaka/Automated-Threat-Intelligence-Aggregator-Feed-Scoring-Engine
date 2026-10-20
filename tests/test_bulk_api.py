"""Unit tests for bulk indicator ingestion API."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app
from cti_core.database import init_db


@pytest.fixture(scope="module", autouse=True)
async def setup_db():
    await init_db()


@pytest.mark.asyncio
async def test_bulk_indicator_ingestion():
    payload = [
        {
            "value": "198.51.100.201",
            "type": "ipv4",
            "source_name": "analyst-submission",
            "severity": "high",
            "tags": ["apt29", "c2"],
        },
        {
            "value": "phishing-bank-login.biz",
            "type": "domain",
            "source_name": "incident-response",
            "severity": "critical",
            "tags": ["phishing"],
        },
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/indicators/bulk", json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["status"] == "success"
        assert data["submitted"] == 2
        assert data["processed"] == 2


@pytest.mark.asyncio
async def test_bulk_indicator_empty():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/indicators/bulk", json=[])
        assert res.status_code == 400
