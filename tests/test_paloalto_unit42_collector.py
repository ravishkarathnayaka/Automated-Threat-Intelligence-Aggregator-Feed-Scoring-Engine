"""Unit tests for Palo Alto Unit 42 collector."""

import pytest
from cti_core.collectors.paloalto_unit42_collector import PaloAltoUnit42Collector


@pytest.mark.asyncio
async def test_paloalto_unit42_mock_collection():
    collector = PaloAltoUnit42Collector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "paloalto_unit42"
    assert items[0]["source_weight"] == 0.92
    assert "unit42" in items[0]["tags"]
    assert any(i["type"] == "ipv4" for i in items)
    assert any(i["type"] == "sha256" for i in items)
