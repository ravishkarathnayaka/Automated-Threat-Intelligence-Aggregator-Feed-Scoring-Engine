"""Integration tests for extended SIEM and Cloud export API endpoints."""

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
async def test_elastic_ndjson_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/elastic.ndjson?min_score=50")
        assert res.status_code == 200
        assert "application/x-ndjson" in res.headers["content-type"]
        assert '{"index":' in res.text


@pytest.mark.asyncio
async def test_wazuh_cdb_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/wazuh.cdb?min_score=50")
        assert res.status_code == 200
        assert ":" in res.text


@pytest.mark.asyncio
async def test_aws_firewall_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/aws-firewall.json?min_score=50")
        assert res.status_code == 200
        data = res.json()
        assert "RuleGroup" in data


@pytest.mark.asyncio
async def test_sigma_yml_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/sigma.yml?min_score=50")
        assert res.status_code == 200
        assert "category: network_connection" in res.text


@pytest.mark.asyncio
async def test_sentinelone_s1ql_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/sentinelone.s1ql?min_score=50")
        assert res.status_code == 200


@pytest.mark.asyncio
async def test_sentinel_kql_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/kql.txt?min_score=50")
        assert res.status_code == 200


@pytest.mark.asyncio
async def test_crowdstrike_csv_export_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/export/crowdstrike.csv?min_score=50")
        assert res.status_code == 200
        assert "type,value,action" in res.text
