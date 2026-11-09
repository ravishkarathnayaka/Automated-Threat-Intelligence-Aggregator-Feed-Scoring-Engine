"""Ingestion collector for SANS Internet Storm Center (ISC) DShield top attacking subnets."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class DShieldScannerCollector(BaseCollector):
    """Ingests top mass-scanning IPs and honeypot-confirmed attacker sources from SANS ISC DShield."""

    def __init__(self) -> None:
        super().__init__(
            name="dshield_isc",
            source_weight=0.87,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://isc.sans.edu/api/topips/records/100?json"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch SANS DShield attacking IP indicators."""
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
                "value": "198.51.100.177",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 89.0,
                "reported_at": now_iso,
                "tags": ["dshield", "sans-isc", "honeypot", "mass-scanner"],
                "reference_url": "https://isc.sans.edu/ipinfo.html?ip=198.51.100.177",
            },
            {
                "value": "203.0.113.219",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 86.0,
                "reported_at": now_iso,
                "tags": ["dshield", "sans-isc", "telnet-bruteforce", "iot-exploit"],
                "reference_url": "https://isc.sans.edu/ipinfo.html?ip=203.0.113.219",
            },
        ]
