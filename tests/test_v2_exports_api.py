"""Integration tests for modern v2 enterprise export API endpoints."""

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
async def test_splunk_lookup_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/splunk.csv?min_score=50")
        assert res.status_code == 200
        assert "text/csv" in res.headers["content-type"]
        assert "threat_key,indicator,type,confidence" in res.text


@pytest.mark.asyncio
async def test_palo_alto_edl_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/palo-alto-edl.txt?min_score=50&category=ip")
        assert res.status_code == 200
        assert "text/plain" in res.headers["content-type"]
        assert "# Palo Alto PAN-OS External Dynamic List" in res.text


@pytest.mark.asyncio
async def test_tanium_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/tanium.json?min_score=50")
        assert res.status_code == 200
        assert "application/json" in res.headers["content-type"]
        data = res.json()
        assert "threat_intel_iocs" in data


@pytest.mark.asyncio
async def test_snort3_rules_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/snort3.rules?min_score=50")
        assert res.status_code == 200
        assert "text/plain" in res.headers["content-type"]
        assert "Snort 3 IPS Ruleset" in res.text


@pytest.mark.asyncio
async def test_vyos_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/vyos.sh?min_score=50")
        assert res.status_code == 200
        assert "text/plain" in res.headers["content-type"]
        assert "set firewall group address-group" in res.text
