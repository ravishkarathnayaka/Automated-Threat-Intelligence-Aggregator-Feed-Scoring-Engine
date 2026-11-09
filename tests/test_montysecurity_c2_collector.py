"""Unit tests for MontySecurity C2 Tracker collector."""

import pytest
from cti_core.collectors.montysecurity_c2_collector import MontySecurityC2Collector


@pytest.mark.asyncio
async def test_montysecurity_c2_mock_collection():
    collector = MontySecurityC2Collector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) == 2
    assert items[0]["source"] == "montysecurity_c2"
    assert items[0]["source_weight"] == 0.92
    assert "c2-tracker" in items[0]["tags"]
    assert all(i["type"] == "ipv4" for i in items)
