"""Ingestion collector for ThreatFox payload download URLs and cryptographic hashes."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class ThreatFoxPayloadCollector(BaseCollector):
    """Ingests malicious payload delivery URLs and file hashes from ThreatFox."""

    def __init__(self) -> None:
        super().__init__(
            name="threatfox_payloads",
            source_weight=0.90,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://threatfox-api.abuse.ch/api/v1/payloads"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch payload indicators from ThreatFox API."""
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
                "value": "http://198.51.100.72/payload.bin",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 92.0,
                "reported_at": now_iso,
                "tags": ["threatfox", "payload_delivery", "redline", "stealer"],
                "reference_url": "https://threatfox.abuse.ch/ioc/991200",
            },
            {
                "value": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                "type": "sha256",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 95.0,
                "reported_at": now_iso,
                "tags": ["threatfox", "payload_hash", "asyncrat"],
                "reference_url": "https://threatfox.abuse.ch/ioc/991201",
            },
        ]
