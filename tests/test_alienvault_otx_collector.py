"""Unit tests for AlienVault OTX collector."""

import pytest
from cti_core.collectors.alienvault_otx_collector import AlienVaultOTXCollector


@pytest.mark.asyncio
async def test_alienvault_otx_mock_collection():
    collector = AlienVaultOTXCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "alienvault_otx"
    assert items[0]["source_weight"] == 0.82
    assert "alienvault" in items[0]["tags"]
    assert any(i["type"] == "ipv4" for i in items)
    assert any(i["type"] == "domain" for i in items)
