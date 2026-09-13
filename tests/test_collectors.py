"""Unit tests verifying collectors and mock feed ingestion."""

import pytest

from cti_core.collectors.abuseipdb import AbuseIPDBCollector
from cti_core.collectors.cisa_kev import CISAKEVCollector
from cti_core.collectors.urlhaus import URLhausCollector


@pytest.mark.asyncio
async def test_abuseipdb_mock_collection():
    """Verify AbuseIPDB collector fallback to mock feed."""
    collector = AbuseIPDBCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) > 0
    assert any("185.220.101.5" in item["value"] for item in items)
    assert items[0]["source"] == "abuseipdb"


@pytest.mark.asyncio
async def test_urlhaus_mock_collection():
    """Verify URLhaus collector fallback to mock feed."""
    collector = URLhausCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) > 0
    assert any("mozi" in str(item["tags"]) for item in items)
    assert items[0]["source"] == "urlhaus"


@pytest.mark.asyncio
async def test_cisa_kev_mock_collection():
    """Verify CISA KEV collector fallback to mock feed."""
    collector = CISAKEVCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) > 0
    assert any("CVE-2021-44228" in item["value"] for item in items)
    assert items[0]["source"] == "cisa_kev"
    assert items[0]["source_weight"] == 1.00
