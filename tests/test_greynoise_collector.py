"""Unit tests for GreyNoise collector."""

import pytest
from cti_core.collectors.greynoise import GreyNoiseCollector


@pytest.mark.asyncio
async def test_greynoise_collection():
    collector = GreyNoiseCollector()
    collector.offline_mode = True

    items = await collector.collect()
    assert len(items) == 2
    for item in items:
        assert item["source"] == "greynoise"
        assert item["type"] == "ipv4"
        assert "greynoise" in item["tags"]
        assert "reference_url" in item
