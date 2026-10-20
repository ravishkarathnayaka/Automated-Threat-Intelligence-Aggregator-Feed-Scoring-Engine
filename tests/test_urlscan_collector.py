"""Unit tests for urlscan.io collector."""

import pytest
from cti_core.collectors.urlscan import URLScanCollector


@pytest.mark.asyncio
async def test_urlscan_mock_collection():
    collector = URLScanCollector()
    collector.offline_mode = True

    items = await collector.collect()
    assert len(items) >= 2
    for item in items:
        assert item["type"] == "url"
        assert item["source"] == "urlscan"
        assert item["reported_confidence"] >= 80.0
        assert "urlscan" in item["tags"]
        assert "reference_url" in item
