"""Unit tests for SSLBL botnet collector."""

import pytest
from cti_core.collectors.sslbl_botnet_collector import SSLBLBotnetCollector


@pytest.mark.asyncio
async def test_sslbl_botnet_collector_mock():
    collector = SSLBLBotnetCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 1
    assert items[0]["type"] == "ipv4"
    assert items[0]["source"] == "sslbl_botnet"
    assert "ssl-c2" in items[0]["tags"]
