"""Unit tests for Stratosphere IPS collector."""

import pytest
from cti_core.collectors.stratosphere_ips_collector import StratosphereIPSCollector


@pytest.mark.asyncio
async def test_stratosphere_ips_mock_collection():
    collector = StratosphereIPSCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "stratosphere_ips"
    assert items[0]["source_weight"] == 0.88
    assert "stratosphere" in items[0]["tags"]
    assert all(i["type"] == "ipv4" for i in items)
