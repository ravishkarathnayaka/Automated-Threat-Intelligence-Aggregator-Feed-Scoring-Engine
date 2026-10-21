"""Unit tests for PhishTank collector."""

import pytest
from cti_core.collectors.phishtank import PhishTankCollector


@pytest.mark.asyncio
async def test_phishtank_collection():
    collector = PhishTankCollector()
    collector.offline_mode = True

    items = await collector.collect()
    assert len(items) == 2
    for item in items:
        assert item["source"] == "phishtank"
        assert item["type"] == "url"
        assert item["reported_confidence"] >= 90.0
        assert "verified-phishing" in item["tags"]
