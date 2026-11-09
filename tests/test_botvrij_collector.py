"""Unit tests for Botvrij.eu OSINT IOC collector."""

import pytest
from cti_core.collectors.botvrij_collector import BotvrijCollector


@pytest.mark.asyncio
async def test_botvrij_mock_collection():
    collector = BotvrijCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "botvrij_eu"
    assert items[0]["source_weight"] == 0.84
    assert "botvrij" in items[0]["tags"]
    assert any(i["type"] == "ipv4" for i in items)
    assert any(i["type"] == "domain" for i in items)
