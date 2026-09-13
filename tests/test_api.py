"""Integration tests for FastAPI endpoints, indicator search, and enforcement exports."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app
from cti_core.database import AsyncSessionLocal, init_db
from cti_core.pipeline import global_pipeline


@pytest.fixture(scope="module", autouse=True)
async def setup_test_database():
    """Ensure database schema is created and synthetic data seeded for tests."""
    await init_db()
    async with AsyncSessionLocal() as session:
        await global_pipeline.run_pipeline(session, use_live=False, skip_enrichment=True)


@pytest.mark.asyncio
async def test_health_check():
    """Verify health endpoint."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_query_indicators_by_type_and_score():
    """Verify filtering indicators by IP and score threshold."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/indicators?type=ip&min_score=50")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        for item in data:
            assert item["type"] in ("ipv4", "ipv6")
            assert item["confidence_score"] >= 50.0


@pytest.mark.asyncio
async def test_create_and_score_single_indicator():
    """Verify manual submission of an indicator with automatic scoring."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "value": "hxxps://malicious-test-stealer[.]org/gate.php",
            "source_name": "manual_entry",
            "tags": ["stealer", "test"],
        }
        response = await client.post("/api/v1/indicators", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert data["normalized_value"] == "https://malicious-test-stealer.org/gate.php"
        assert data["type"] == "url"
        assert data["confidence_score"] > 0.0
        assert data["is_whitelisted"] is False


@pytest.mark.asyncio
async def test_firewall_plaintext_export():
    """Verify plaintext firewall newline-separated export."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/export/firewall.txt?min_score=60")
        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]
        text = response.text
        assert "# Automated Threat Intelligence Firewall Blocklist" in text
        # 8.8.8.8 should NOT be present (whitelisted)
        assert "8.8.8.8" not in text
        # Confirm presence of malicious IPs
        assert "185.220.101.5" in text or "194.26.29.112" in text


@pytest.mark.asyncio
async def test_stix_bundle_export():
    """Verify STIX 2.1 JSON export endpoint."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/export/stix.json?min_score=50")
        assert response.status_code == 200
        payload = response.json()
        assert payload["type"] == "bundle"
        assert len(payload["objects"]) > 0


@pytest.mark.asyncio
async def test_dns_rpz_export():
    """Verify DNS Response Policy Zone (RPZ) file export."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/export/dns-rpz.zone?min_score=50")
        assert response.status_code == 200
        assert "CNAME ." in response.text
        assert "SOA" in response.text
