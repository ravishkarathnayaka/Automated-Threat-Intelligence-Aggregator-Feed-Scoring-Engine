"""Unit tests for Curated Intelligence open threat telemetry collector."""

import pytest
from cti_core.collectors.curated_intel_collector import CuratedIntelCollector


@pytest.mark.asyncio
async def test_curated_intel_mock_collection():
    collector = CuratedIntelCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "curated_intelligence"
    assert items[0]["source_weight"] == 0.91
    assert "curated-intel" in items[0]["tags"]
    assert any(i["type"] == "domain" for i in items)
    assert any(i["type"] == "ipv4" for i in items)
