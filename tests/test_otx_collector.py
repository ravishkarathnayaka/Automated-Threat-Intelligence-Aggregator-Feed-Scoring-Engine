"""Unit tests for AlienVault OTX collector."""

import pytest
from cti_core.collectors.otx_collector import OTXCollector


@pytest.mark.asyncio
async def test_otx_mock_collection():
    collector = OTXCollector()
    collector.offline_mode = True

    items = await collector.collect()
    assert len(items) >= 2
    for item in items:
        assert item["source"] == "alienvault_otx"
        assert item["reported_confidence"] >= 80.0
        assert "otx-pulse" in item["tags"]
        assert "reference_url" in item
