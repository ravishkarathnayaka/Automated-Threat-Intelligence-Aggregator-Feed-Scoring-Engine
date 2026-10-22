"""Unit tests for ViriBack collector."""

import pytest
from cti_core.collectors.viriback_tracker_collector import ViriBackTrackerCollector


@pytest.mark.asyncio
async def test_viriback_collector_mock():
    collector = ViriBackTrackerCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 1
    assert items[0]["type"] == "url"
    assert items[0]["source"] == "viriback_tracker"
    assert "c2-panel" in items[0]["tags"]
