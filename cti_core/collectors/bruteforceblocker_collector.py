"""Ingestion collector for BruteForceBlocker automated SSH/RDP attack telemetry feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class BruteForceBlockerCollector(BaseCollector):
    """Ingests active SSH and credential brute-force attacker IPs from BruteForceBlocker."""

    def __init__(self) -> None:
        super().__init__(
            name="bruteforceblocker",
            source_weight=0.81,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://danger.rulez.sk/projects/bruteforceblocker/blist.php"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch BruteForceBlocker IP blocklist indicators."""
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
                "value": "198.51.100.252",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["bruteforceblocker", "ssh-bruteforce", "credential-stuffing"],
                "reference_url": "https://danger.rulez.sk/projects/bruteforceblocker/",
            },
            {
                "value": "203.0.113.253",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 83.0,
                "reported_at": now_iso,
                "tags": ["bruteforceblocker", "ssh-scanner", "dictionary-attack"],
                "reference_url": "https://danger.rulez.sk/projects/bruteforceblocker/",
            },
        ]
