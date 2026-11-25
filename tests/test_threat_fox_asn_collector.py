"""Unit tests for ThreatFox ASN collector."""

import pytest
from cti_core.collectors.threat_fox_asn_collector import ThreatFoxASNCollector


@pytest.mark.asyncio
async def test_threatfox_asn_mock_collection():
    collector = ThreatFoxASNCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) == 2
    assert items[0]["source"] == "threatfox_asn"
    assert items[0]["source_weight"] == 0.90
    assert "threatfox" in items[0]["tags"]
    assert any("asn" in t for t in items[0]["tags"])
