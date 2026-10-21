"""Unit tests for CINS Army collector."""

import pytest
from cti_core.collectors.cinsscore import CINSArmyCollector


@pytest.mark.asyncio
async def test_cins_collection():
    collector = CINSArmyCollector()
    collector.offline_mode = True

    items = await collector.collect()
    assert len(items) == 2
    for item in items:
        assert item["source"] == "cins_army"
        assert item["type"] == "ipv4"
        assert item["reported_confidence"] >= 80.0
        assert "cins-army" in item["tags"]
