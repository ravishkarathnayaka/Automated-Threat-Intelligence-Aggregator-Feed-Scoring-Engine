"""Unit tests for CertStream collector."""

import pytest
from cti_core.collectors.certstream_collector import CertStreamCollector


@pytest.mark.asyncio
async def test_certstream_mock_collection():
    collector = CertStreamCollector()
    collector.offline_mode = True
    items = await collector.collect()

    assert len(items) >= 2
    assert items[0]["source"] == "certstream_ct"
    assert items[0]["source_weight"] == 0.81
    assert "certstream" in items[0]["tags"]
    assert all(i["type"] == "domain" for i in items)
