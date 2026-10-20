"""Unit tests verifying OpenPhish collector parsing and mock fallback."""

import pytest

from cti_core.collectors.openphish import OpenPhishCollector


@pytest.mark.asyncio
async def test_openphish_mock_collection():
    """Verify OpenPhish collector mock collection."""
    collector = OpenPhishCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 2
    assert any("secure-login-account-verify" in item["value"] for item in items)
    assert items[0]["source"] == "openphish"
    assert items[0]["type"] == "url"
    assert items[0]["source_weight"] == 0.85


@pytest.mark.asyncio
async def test_openphish_tags():
    """Verify OpenPhish tags contain phishing classification."""
    collector = OpenPhishCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert all("phishing" in i["tags"] for i in items)
    assert all("openphish" in i["tags"] for i in items)
