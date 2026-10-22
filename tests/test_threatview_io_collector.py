"""Unit tests for ThreatView.io collector."""

import pytest
from cti_core.collectors.threatview_io_collector import ThreatViewIOCollector


@pytest.mark.asyncio
async def test_threatview_io_collector_mock():
    collector = ThreatViewIOCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 1
    assert items[0]["type"] == "ipv4"
    assert items[0]["source"] == "threatview_io"
    assert "cobalt-strike" in items[0]["tags"]
