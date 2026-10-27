"""Unit tests for IPSum level collector."""

import pytest
from cti_core.collectors.ipsum_level_collector import IPSumLevelCollector


@pytest.mark.asyncio
async def test_ipsum_mock_collection():
    collector = IPSumLevelCollector(min_level=3)
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "ipsum_corroborated"
    assert items[0]["source_weight"] == 0.85
    assert "ipsum" in items[0]["tags"]
    assert "level-3" in items[0]["tags"]
    assert all(i["type"] == "ipv4" for i in items)
