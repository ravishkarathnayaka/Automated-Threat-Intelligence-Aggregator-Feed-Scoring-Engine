"""Unit tests for CyberCrime Tracker collector."""

import pytest
from cti_core.collectors.cybercrime_tracker_collector import CyberCrimeTrackerCollector


@pytest.mark.asyncio
async def test_cybercrime_tracker_mock_collection():
    collector = CyberCrimeTrackerCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "cybercrime_tracker"
    assert items[0]["source_weight"] == 0.86
    assert "cybercrime" in items[0]["tags"]
    assert any(i["type"] == "url" for i in items)
    assert any(i["type"] == "domain" for i in items)
