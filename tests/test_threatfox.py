"""Unit tests verifying ThreatFox collector parsing and mock fallback."""

import pytest

from cti_core.collectors.threatfox import ThreatFoxCollector


@pytest.mark.asyncio
async def test_threatfox_mock_collection():
    """Verify ThreatFox collector mock collection."""
    collector = ThreatFoxCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 2
    assert any("185.220.101.7" in item["value"] for item in items)
    assert any("darknet-command-server.cc" in item["value"] for item in items)
    assert items[0]["source"] == "threatfox"
    assert items[0]["source_weight"] == 0.85


@pytest.mark.asyncio
async def test_threatfox_tags():
    """Verify ThreatFox generates proper malware and threat type tags."""
    collector = ThreatFoxCollector()
    collector.offline_mode = True
    items = await collector.collect()
    ip_item = next(i for i in items if "185.220.101.7" in i["value"])
    assert "threatfox" in ip_item["tags"]
    assert "cobalt-strike" in ip_item["tags"]
