"""Unit tests verifying Blocklist.de collector parsing and mock fallback."""

import pytest

from cti_core.collectors.blocklist_de import BlocklistDeCollector


@pytest.mark.asyncio
async def test_blocklist_de_mock_collection():
    """Verify Blocklist.de collector mock collection."""
    collector = BlocklistDeCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 2
    assert any("194.26.29.115" in item["value"] for item in items)
    assert items[0]["source"] == "blocklist_de"
    assert items[0]["type"] == "ipv4"
    assert items[0]["source_weight"] == 0.80


@pytest.mark.asyncio
async def test_blocklist_de_tags():
    """Verify Blocklist.de tags contain attack classification."""
    collector = BlocklistDeCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert all("brute-force" in i["tags"] for i in items)
    assert all("blocklist-de" in i["tags"] for i in items)
