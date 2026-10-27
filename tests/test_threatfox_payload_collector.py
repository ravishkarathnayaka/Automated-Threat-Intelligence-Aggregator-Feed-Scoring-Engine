"""Unit tests for ThreatFox payload collector."""

import pytest
from cti_core.collectors.threatfox_payload_collector import ThreatFoxPayloadCollector


@pytest.mark.asyncio
async def test_threatfox_payload_mock_collection():
    collector = ThreatFoxPayloadCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "threatfox_payloads"
    assert items[0]["source_weight"] == 0.90
    assert "threatfox" in items[0]["tags"]
    assert any(i["type"] == "url" for i in items)
    assert any(i["type"] == "sha256" for i in items)
