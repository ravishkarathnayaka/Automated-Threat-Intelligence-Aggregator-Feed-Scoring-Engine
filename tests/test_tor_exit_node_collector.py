"""Unit tests for Tor exit node collector."""

import pytest
from cti_core.collectors.tor_exit_node_collector import TorExitNodeCollector


@pytest.mark.asyncio
async def test_tor_exit_node_mock_collection():
    collector = TorExitNodeCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "tor_exit_nodes"
    assert items[0]["source_weight"] == 0.78
    assert "tor" in items[0]["tags"]
    assert all(i["type"] == "ipv4" for i in items)
