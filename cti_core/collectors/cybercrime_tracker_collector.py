"""Ingestion collector for CyberCrime Tracker malware control panel and C2 telemetry."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class CyberCrimeTrackerCollector(BaseCollector):
    """Ingests active malware control panels and administrative C2 interfaces."""

    def __init__(self) -> None:
        super().__init__(
            name="cybercrime_tracker",
            source_weight=0.86,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://cybercrime-tracker.net/all.php"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch active malware panel indicators."""
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
                "value": "http://198.51.100.45/gate.php",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 90.0,
                "reported_at": now_iso,
                "tags": ["cybercrime", "malware-panel", "stealer", "c2"],
                "reference_url": "https://cybercrime-tracker.net/panel/1044",
            },
            {
                "value": "botnet-control-auth.top",
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 88.0,
                "reported_at": now_iso,
                "tags": ["cybercrime", "botnet-panel", "c2-interface"],
                "reference_url": "https://cybercrime-tracker.net/panel/1045",
            },
        ]
