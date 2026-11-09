"""Unit tests for Ransomware.live extortion infrastructure collector."""

import pytest
from cti_core.collectors.ransomware_live_collector import RansomwareLiveCollector


@pytest.mark.asyncio
async def test_ransomware_live_mock_collection():
    collector = RansomwareLiveCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) == 2
    assert items[0]["source"] == "ransomware_live"
    assert items[0]["source_weight"] == 0.91
    assert "ransomware" in items[0]["tags"]
    assert any(i["type"] == "domain" for i in items)
    assert any(i["type"] == "url" for i in items)
