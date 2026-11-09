"""Unit tests for PhishStats real-time phishing feed collector."""

import pytest
from cti_core.collectors.phishstats_collector import PhishStatsCollector


@pytest.mark.asyncio
async def test_phishstats_mock_collection():
    collector = PhishStatsCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) == 2
    assert items[0]["source"] == "phishstats_info"
    assert items[0]["source_weight"] == 0.83
    assert "phishing" in items[0]["tags"]
    assert any(i["type"] == "url" for i in items)
    assert any(i["type"] == "domain" for i in items)
