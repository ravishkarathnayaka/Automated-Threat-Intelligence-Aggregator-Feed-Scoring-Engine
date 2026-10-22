"""Unit tests for Bambenek C2 collector."""

import pytest
from cti_core.collectors.bambenek_c2_collector import BambenekC2Collector


@pytest.mark.asyncio
async def test_bambenek_c2_collector_mock():
    collector = BambenekC2Collector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 1
    assert items[0]["type"] == "domain"
    assert items[0]["source"] == "bambenek_c2"
    assert "c2" in items[0]["tags"]
