"""Unit tests for Rutgers bad hosts collector."""

import pytest
from cti_core.collectors.rutgers_bad_hosts_collector import RutgersBadHostsCollector


@pytest.mark.asyncio
async def test_rutgers_bad_hosts_collector_mock():
    collector = RutgersBadHostsCollector()
    collector.offline_mode = True
    items = await collector.collect()
    assert len(items) >= 1
    assert items[0]["type"] == "ipv4"
    assert items[0]["source"] == "rutgers_bad_hosts"
    assert "bad-host" in items[0]["tags"]
