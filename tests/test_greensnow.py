"""Unit tests for GreenSnow collector."""

import pytest
from cti_core.collectors.greensnow import GreenSnowCollector


@pytest.mark.asyncio
async def test_greensnow_collection():
    collector = GreenSnowCollector()
    collector.offline_mode = True

    items = await collector.collect()
    assert len(items) == 2
    for item in items:
        assert item["source"] == "greensnow"
        assert item["type"] == "ipv4"
        assert item["reported_confidence"] >= 80.0
        assert "greensnow" in item["tags"]
