"""Unit tests for Inversion DNSBL collector."""

import pytest
from cti_core.collectors.inversion_dnsbl_collector import InversionDNSBLCollector


@pytest.mark.asyncio
async def test_inversion_dnsbl_collector_mock():
    collector = InversionDNSBLCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 1
    assert items[0]["type"] == "ipv4"
    assert items[0]["source"] == "inversion_dnsbl"
    assert items[0]["reported_confidence"] == 80.0
