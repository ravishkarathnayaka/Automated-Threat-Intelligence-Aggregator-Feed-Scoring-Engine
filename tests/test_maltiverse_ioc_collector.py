"""Unit tests for Maltiverse threat intelligence collector."""

import pytest
from cti_core.collectors.maltiverse_ioc_collector import MaltiverseIOCCollector


@pytest.mark.asyncio
async def test_maltiverse_mock_collection():
    collector = MaltiverseIOCCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) == 2
    assert items[0]["source"] == "maltiverse_ioc"
    assert items[0]["source_weight"] == 0.87
    assert "maltiverse" in items[0]["tags"]
    assert any(i["type"] == "domain" for i in items)
    assert any(i["type"] == "ipv4" for i in items)
