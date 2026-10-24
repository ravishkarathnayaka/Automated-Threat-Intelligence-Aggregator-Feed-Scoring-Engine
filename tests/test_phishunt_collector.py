"""Unit tests for Phishunt collector."""

import pytest
from cti_core.collectors.phishunt_collector import PhishuntCollector


@pytest.mark.asyncio
async def test_phishunt_mock_collection():
    collector = PhishuntCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "phishunt_feed"
    assert items[0]["source_weight"] == 0.84
    assert "phishing" in items[0]["tags"]
    assert any(i["type"] == "url" for i in items)
    assert any(i["type"] == "domain" for i in items)
