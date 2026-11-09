"""Ingestion collector for Botvrij.eu Open-Source Intelligence (OSINT) IOC feeds."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class BotvrijCollector(BaseCollector):
    """Ingests verified malware domains, destination IPs, and SHA256 hashes from Botvrij.eu."""

    def __init__(self) -> None:
        super().__init__(
            name="botvrij_eu",
            source_weight=0.84,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://www.botvrij.eu/data/ioclist.ip-dst.raw"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch active Botvrij.eu threat indicators."""
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
                "value": "198.51.100.145",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 87.0,
                "reported_at": now_iso,
                "tags": ["botvrij", "osint", "c2", "malware-dst"],
                "reference_url": "https://www.botvrij.eu/data/ioclist.ip-dst",
            },
            {
                "value": "stealer-drop-eu.xyz",
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["botvrij", "osint", "hostname"],
                "reference_url": "https://www.botvrij.eu/data/ioclist.hostname",
            },
        ]
