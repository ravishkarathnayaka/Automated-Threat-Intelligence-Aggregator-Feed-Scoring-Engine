"""Unit tests for VXVault collector."""

import pytest
from cti_core.collectors.vxvault import VXVaultCollector


@pytest.mark.asyncio
async def test_vxvault_collection():
    collector = VXVaultCollector()
    collector.offline_mode = True

    items = await collector.collect()
    assert len(items) == 2
    for item in items:
        assert item["source"] == "vxvault"
        assert item["type"] == "url"
        assert item["reported_confidence"] >= 85.0
        assert "vxvault" in item["tags"]
