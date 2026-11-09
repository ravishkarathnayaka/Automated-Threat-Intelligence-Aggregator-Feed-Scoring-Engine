"""Unit tests for SANS ISC DShield attacking IP collector."""

import pytest
from cti_core.collectors.dshield_scanner_collector import DShieldScannerCollector


@pytest.mark.asyncio
async def test_dshield_scanner_mock_collection():
    collector = DShieldScannerCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) == 2
    assert items[0]["source"] == "dshield_isc"
    assert items[0]["source_weight"] == 0.87
    assert "dshield" in items[0]["tags"]
    assert all(i["type"] == "ipv4" for i in items)
