"""Unit tests for BruteForceBlocker SSH attacker collector."""

import pytest
from cti_core.collectors.bruteforceblocker_collector import BruteForceBlockerCollector


@pytest.mark.asyncio
async def test_bruteforceblocker_mock_collection():
    collector = BruteForceBlockerCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) == 2
    assert items[0]["source"] == "bruteforceblocker"
    assert items[0]["source_weight"] == 0.81
    assert "ssh-bruteforce" in items[0]["tags"]
    assert all(i["type"] == "ipv4" for i in items)
