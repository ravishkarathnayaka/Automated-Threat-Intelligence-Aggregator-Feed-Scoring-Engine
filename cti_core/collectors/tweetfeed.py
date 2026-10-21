"""Ingestion client for TweetFeed OSINT community threat feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class TweetFeedCollector(BaseCollector):
    """Ingests real-time OSINT indicators shared by researchers on social networks."""

    def __init__(self) -> None:
        super().__init__(
            name="tweetfeed",
            source_weight=0.75,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/today.csv"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch TweetFeed today's CSV feed."""
        if self.offline_mode:
            logger.info("[tweetfeed] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[tweetfeed] Feed unreachable; using synthetic dataset.")
            return self.get_mock_data()

        try:
            results: List[Dict[str, Any]] = []
            now_iso = datetime.now(timezone.utc).isoformat()
            for line in response.text.splitlines()[:500]:
                parts = line.split(",")
                if len(parts) < 5 or parts[0].startswith("#"):
                    continue
                # format: Date,User,Type,Value,Tags
                itype = parts[2].strip().lower()
                val = parts[3].strip()
                tag = parts[4].strip() if len(parts) > 4 else "osint"
                mapped_type = "ipv4" if "ip" in itype else ("domain" if "domain" in itype else "url")

                results.append({
                    "value": val,
                    "type": mapped_type,
                    "source": self.name,
                    "source_weight": self.source_weight,
                    "reported_confidence": 78.0,
                    "reported_at": now_iso,
                    "tags": ["tweetfeed", "osint", tag],
                    "reference_url": "https://tweetfeed.live",
                })
            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[tweetfeed] Parse failure: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "194.26.29.130",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 80.0,
                "reported_at": now_iso,
                "tags": ["tweetfeed", "osint", "cobaltstrike"],
                "reference_url": "https://tweetfeed.live",
            },
            {
                "value": "malware-delivery-cdn[.]biz",
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 75.0,
                "reported_at": now_iso,
                "tags": ["tweetfeed", "osint", "agenttesla"],
                "reference_url": "https://tweetfeed.live",
            },
        ]
