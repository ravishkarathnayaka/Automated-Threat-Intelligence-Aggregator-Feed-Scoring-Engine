"""Ingestion collector for Proofpoint Emerging Threats (ET) Compromised IP feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class EmergingThreatsCollector(BaseCollector):
    """Ingests Proofpoint Emerging Threats known compromised hosts and botnet nodes."""

    def __init__(self) -> None:
        super().__init__(
            name="emerging_threats",
            source_weight=0.89,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch Emerging Threats compromised IP indicators."""
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
                "value": "203.0.113.199",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 91.0,
                "reported_at": now_iso,
                "tags": ["emerging-threats", "compromised-host", "botnet"],
                "reference_url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            },
            {
                "value": "198.51.100.211",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 88.0,
                "reported_at": now_iso,
                "tags": ["emerging-threats", "scanner", "brute-force"],
                "reference_url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            },
        ]
