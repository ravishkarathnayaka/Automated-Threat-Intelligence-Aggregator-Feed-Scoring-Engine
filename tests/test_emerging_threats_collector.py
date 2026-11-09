"""Unit tests for Proofpoint Emerging Threats compromised IP collector."""

import pytest
from cti_core.collectors.emerging_threats_collector import EmergingThreatsCollector


@pytest.mark.asyncio
async def test_emerging_threats_mock_collection():
    collector = EmergingThreatsCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) == 2
    assert items[0]["source"] == "emerging_threats"
    assert items[0]["source_weight"] == 0.89
    assert "emerging-threats" in items[0]["tags"]
    assert all(i["type"] == "ipv4" for i in items)
