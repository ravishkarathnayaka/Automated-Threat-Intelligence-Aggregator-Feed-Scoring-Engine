"""Unit tests for Spamhaus DROP collector."""

import pytest
from cti_core.collectors.spamhaus_drop import SpamhausDROPCollector


@pytest.mark.asyncio
async def test_spamhaus_collection():
    collector = SpamhausDROPCollector()
    collector.offline_mode = True

    items = await collector.collect()
    assert len(items) == 2
    for item in items:
        assert item["source"] == "spamhaus_drop"
        assert "/" in item["value"]  # CIDR subnet format
        assert item["reported_confidence"] >= 95.0
        assert "spamhaus-drop" in item["tags"]
