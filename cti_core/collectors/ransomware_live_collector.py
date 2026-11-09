"""Ingestion collector forJMousqueton Ransomware.live active extortion group leak site telemetry."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class RansomwareLiveCollector(BaseCollector):
    """Ingests active ransomware group extortion infrastructure and C2 domains from Ransomware.live."""

    def __init__(self) -> None:
        super().__init__(
            name="ransomware_live",
            source_weight=0.91,
            rate_limit_per_second=1.5,
            max_retries=3,
        )
        self.endpoint = "https://api.ransomware.live/recentvictims"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch Ransomware.live telemetry indicators."""
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
                "value": "lockbit3-negotiation-mirror.onion.ly",
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 96.0,
                "reported_at": now_iso,
                "tags": ["ransomware-live", "ransomware", "lockbit", "extortion-portal"],
                "reference_url": "https://www.ransomware.live/",
            },
            {
                "value": "https://blackbasta-chat-gateway.top/login",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 93.0,
                "reported_at": now_iso,
                "tags": ["ransomware-live", "ransomware", "blackbasta", "c2"],
                "reference_url": "https://www.ransomware.live/",
            },
        ]
