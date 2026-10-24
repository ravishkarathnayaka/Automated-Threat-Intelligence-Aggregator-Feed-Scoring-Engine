"""Unit tests for Ransomware tracker collector."""

import pytest
from cti_core.collectors.ransomware_tracker_collector import RansomwareTrackerCollector


@pytest.mark.asyncio
async def test_ransomware_tracker_mock_collection():
    collector = RansomwareTrackerCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "ransomware_tracker"
    assert items[0]["source_weight"] == 0.94
    assert "ransomware" in items[0]["tags"]
    assert any(i["type"] == "domain" for i in items)
    assert any(i["type"] == "ipv4" for i in items)
