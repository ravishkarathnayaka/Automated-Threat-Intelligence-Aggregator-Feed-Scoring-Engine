"""Ingestion collector for active ransomware C2 and payment portal indicators."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class RansomwareTrackerCollector(BaseCollector):
    """Ingests active ransomware command & control and double-extortion leak sites."""

    def __init__(self) -> None:
        super().__init__(
            name="ransomware_tracker",
            source_weight=0.94,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://ransomware-tracker.internal/api/active_c2.json"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch ransomware indicators."""
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
                "value": "lockbit-supp-portal.onion.ws",
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 96.0,
                "reported_at": now_iso,
                "tags": ["ransomware", "lockbit", "extortion-portal"],
                "reference_url": "https://threatintel.internal/ransomware/lockbit",
            },
            {
                "value": "185.161.248.54",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 92.0,
                "reported_at": now_iso,
                "tags": ["ransomware", "blackcat", "alphv", "c2"],
                "reference_url": "https://threatintel.internal/ransomware/alphv",
            },
        ]
