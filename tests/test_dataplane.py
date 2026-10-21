"""Unit tests for Dataplane collector."""

import pytest
from cti_core.collectors.dataplane import DataplaneCollector


@pytest.mark.asyncio
async def test_dataplane_collection():
    collector = DataplaneCollector()
    collector.offline_mode = True

    items = await collector.collect()
    assert len(items) == 2
    for item in items:
        assert item["source"] == "dataplane"
        assert item["type"] == "ipv4"
        assert item["reported_confidence"] >= 80.0
        assert "dataplane" in item["tags"]
