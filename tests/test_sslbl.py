"""Unit tests verifying SSLBL SHA1 certificate collector parsing and mock fallback."""

import pytest

from cti_core.collectors.sslbl import SSLBLCollector


@pytest.mark.asyncio
async def test_sslbl_mock_collection():
    """Verify SSLBL collector mock collection."""
    collector = SSLBLCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 2
    assert any("2f4581f18544e3fa338a0b0d3667c3b999c086d4" in item["value"] for item in items)
    assert items[0]["source"] == "sslbl"
    assert items[0]["type"] == "sha1"
    assert items[0]["source_weight"] == 0.85


@pytest.mark.asyncio
async def test_sslbl_tags():
    """Verify SSLBL tags contain TLS and malware metadata."""
    collector = SSLBLCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert all("ssl-cert" in i["tags"] for i in items)
    assert all("malicious-tls" in i["tags"] for i in items)
