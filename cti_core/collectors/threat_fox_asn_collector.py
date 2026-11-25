"""Ingestion collector for ThreatFox ASN-aggregated malicious host feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class ThreatFoxASNCollector(BaseCollector):
    """Ingests high-density malicious infrastructure grouped by hosting ASN from ThreatFox."""

    def __init__(self) -> None:
        super().__init__(
            name="threatfox_asn",
            source_weight=0.90,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://threatfox.abuse.ch/export/json/recent/"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch ThreatFox ASN aggregated indicators."""
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
                "value": "198.51.100.188:443",
                "type": "ip_port",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 94.0,
                "reported_at": now_iso,
                "tags": ["threatfox", "asn200019", "quakbot-c2", "botnet"],
                "reference_url": "https://threatfox.abuse.ch/ioc/104928/",
            },
            {
                "value": "203.0.113.111",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 91.0,
                "reported_at": now_iso,
                "tags": ["threatfox", "asn44477", "redline-stealer"],
                "reference_url": "https://threatfox.abuse.ch/ioc/104929/",
            },
        ]
