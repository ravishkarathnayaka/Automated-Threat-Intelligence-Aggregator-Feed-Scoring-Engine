"""Unit tests verifying Feodo Tracker C2 collector logic and parsing."""

import pytest

from cti_core.collectors.feodo_tracker import FeodoTrackerCollector


@pytest.mark.asyncio
async def test_feodo_tracker_mock_collection():
    """Verify Feodo Tracker collector fallback to mock feed."""
    collector = FeodoTrackerCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 3
    assert any("185.244.150.84" in item["value"] for item in items)
    assert items[0]["source"] == "feodo_tracker"
    assert items[0]["type"] == "ipv4"
    assert items[0]["source_weight"] == 0.90


@pytest.mark.asyncio
async def test_feodo_tracker_tag_metadata():
    """Verify Feodo Tracker generates proper malware family and C2 status tags."""
    collector = FeodoTrackerCollector()
    collector.offline_mode = True
    items = await collector.collect()

    dridex_item = next(i for i in items if "185.244.150.84" in i["value"])
    assert "dridex" in dridex_item["tags"]
    assert "c2" in dridex_item["tags"]
    assert "feodo-tracker" in dridex_item["tags"]
    assert "status-online" in dridex_item["tags"]
    assert dridex_item["reported_confidence"] == 95.0
