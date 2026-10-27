"""Unit tests for AbuseIPDB blacklist collector."""

import pytest
from cti_core.collectors.abuseipdb_blacklist_collector import AbuseIPDBBlacklistCollector


@pytest.mark.asyncio
async def test_abuseipdb_mock_collection():
    collector = AbuseIPDBBlacklistCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "abuseipdb_blacklist"
    assert items[0]["source_weight"] == 0.88
    assert "abuseipdb" in items[0]["tags"]
    assert all(i["type"] == "ipv4" for i in items)
