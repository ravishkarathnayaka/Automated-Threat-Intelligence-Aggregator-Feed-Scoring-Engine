"""Unit tests for OpenPhish global collector."""

import pytest
from cti_core.collectors.openphish_global_collector import OpenPhishGlobalCollector


@pytest.mark.asyncio
async def test_openphish_mock_collection():
    collector = OpenPhishGlobalCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "openphish_global"
    assert items[0]["source_weight"] == 0.87
    assert "openphish" in items[0]["tags"]
    assert all(i["type"] == "url" for i in items)
