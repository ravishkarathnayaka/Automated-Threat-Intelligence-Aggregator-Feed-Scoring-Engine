"""Unit tests for TweetFeed collector."""

import pytest
from cti_core.collectors.tweetfeed import TweetFeedCollector


@pytest.mark.asyncio
async def test_tweetfeed_collection():
    collector = TweetFeedCollector()
    collector.offline_mode = True

    items = await collector.collect()
    assert len(items) == 2
    for item in items:
        assert item["source"] == "tweetfeed"
        assert item["reported_confidence"] >= 70.0
        assert "tweetfeed" in item["tags"]
        assert "osint" in item["tags"]
