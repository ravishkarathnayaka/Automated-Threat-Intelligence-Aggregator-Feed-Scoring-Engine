"""Unit tests for Feodo IP blocklist collector."""

import pytest
from cti_core.collectors.feodo_ip_blocklist_collector import FeodoIPBlocklistCollector


@pytest.mark.asyncio
async def test_feodo_ip_collector_mock():
    collector = FeodoIPBlocklistCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 1
    assert items[0]["type"] == "ipv4"
    assert items[0]["source"] == "feodo_ip_blocklist"
    assert items[0]["reported_confidence"] == 95.0
