"""Unit tests for Cryptojacking pool collector."""

import pytest
from cti_core.collectors.cryptojacking_pool_collector import CryptojackingPoolCollector


@pytest.mark.asyncio
async def test_cryptojacking_pool_mock_collection():
    collector = CryptojackingPoolCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "cryptojacking_pools"
    assert items[0]["source_weight"] == 0.85
    assert "cryptojacking" in items[0]["tags"]
    assert any(i["type"] == "domain" for i in items)
    assert any(i["type"] == "ipv4" for i in items)
