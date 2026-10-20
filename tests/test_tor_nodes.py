"""Unit tests verifying Tor exit nodes collector parsing and mock fallback."""

import pytest

from cti_core.collectors.tor_nodes import TorExitNodesCollector


@pytest.mark.asyncio
async def test_tor_nodes_mock_collection():
    """Verify Tor exit nodes collector mock fallback."""
    collector = TorExitNodesCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 2
    assert any("185.220.101.5" in item["value"] for item in items)
    assert items[0]["source"] == "tor_exit_nodes"
    assert items[0]["source_weight"] == 0.75


@pytest.mark.asyncio
async def test_tor_nodes_tags():
    """Verify Tor exit node tags contain anonymizer metadata."""
    collector = TorExitNodesCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert all("tor-exit" in i["tags"] for i in items)
    assert all("anonymizer" in i["tags"] for i in items)
