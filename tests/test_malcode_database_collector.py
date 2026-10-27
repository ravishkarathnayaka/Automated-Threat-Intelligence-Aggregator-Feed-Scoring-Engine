"""Unit tests for Malcode database collector."""

import pytest
from cti_core.collectors.malcode_database_collector import MalcodeDatabaseCollector


@pytest.mark.asyncio
async def test_malcode_mock_collection():
    collector = MalcodeDatabaseCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "malcode_database"
    assert items[0]["source_weight"] == 0.84
    assert "malcode" in items[0]["tags"]
    assert any(i["type"] == "domain" for i in items)
    assert any(i["type"] == "ipv4" for i in items)
