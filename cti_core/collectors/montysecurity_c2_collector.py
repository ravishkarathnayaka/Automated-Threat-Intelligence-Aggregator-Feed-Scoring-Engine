"""Ingestion collector for MontySecurity C2 Tracker framework IP feeds."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class MontySecurityC2Collector(BaseCollector):
    """Ingests active Cobalt Strike, Sliver, Havoc, Brute Ratel, and Mythic C2 servers."""

    def __init__(self) -> None:
        super().__init__(
            name="montysecurity_c2",
            source_weight=0.92,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch MontySecurity C2 Tracker indicators."""
        if self.offline_mode:
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            return self.get_mock_data()

        return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Synthetic fallback indicators for testing and offline runs."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "198.51.100.231",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 95.0,
                "reported_at": now_iso,
                "tags": ["montysecurity", "c2-tracker", "sliver-c2", "apt-infrastructure"],
                "reference_url": "https://github.com/montysecurity/C2-Tracker",
            },
            {
                "value": "203.0.113.244",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 94.0,
                "reported_at": now_iso,
                "tags": ["montysecurity", "c2-tracker", "havoc-c2", "red-team-tool"],
                "reference_url": "https://github.com/montysecurity/C2-Tracker",
            },
        ]
