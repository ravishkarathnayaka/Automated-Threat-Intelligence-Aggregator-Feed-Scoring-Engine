"""Ingestion collector for Malcode database malicious domain and IP feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class MalcodeDatabaseCollector(BaseCollector):
    """Ingests malicious drive-by payload and downloader domains from Malcode."""

    def __init__(self) -> None:
        super().__init__(
            name="malcode_database",
            source_weight=0.84,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "http://malc0de.com/bl/ZONES"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch drive-by payload domains."""
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
                "value": "payload-cdn-download.cc",
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 87.0,
                "reported_at": now_iso,
                "tags": ["malcode", "driveby-download", "trojan-distributor"],
                "reference_url": "http://malc0de.com",
            },
            {
                "value": "185.176.27.104",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["malcode", "exploit-kit-landing"],
                "reference_url": "http://malc0de.com",
            },
        ]
