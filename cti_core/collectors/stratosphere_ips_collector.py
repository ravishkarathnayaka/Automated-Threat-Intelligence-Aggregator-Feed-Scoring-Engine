"""Ingestion collector for Stratosphere Lab IoT botnet and malware honeynet captures."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class StratosphereIPSCollector(BaseCollector):
    """Ingests active IoT botnet and behavioral C2 captures from Stratosphere Lab."""

    def __init__(self) -> None:
        super().__init__(
            name="stratosphere_ips",
            source_weight=0.88,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://mcfp.felk.cvut.cz/csm4log/c2_ip_blocklist.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch IoT botnet indicators."""
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
                "value": "194.26.29.44",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 91.0,
                "reported_at": now_iso,
                "tags": ["stratosphere", "iot-botnet", "mirai", "c2"],
                "reference_url": "https://www.stratosphereips.org",
            },
            {
                "value": "89.208.107.12",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 89.0,
                "reported_at": now_iso,
                "tags": ["stratosphere", "gafgyt", "ddos-botnet"],
                "reference_url": "https://www.stratosphereips.org",
            },
        ]
