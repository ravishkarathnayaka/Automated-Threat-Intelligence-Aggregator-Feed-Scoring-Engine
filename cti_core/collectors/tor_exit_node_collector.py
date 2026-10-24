"""Ingestion collector for authoritative Tor Project exit relay consensus."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class TorExitNodeCollector(BaseCollector):
    """Ingests official Tor exit relay IP addresses for network egress correlation."""

    def __init__(self) -> None:
        super().__init__(
            name="tor_exit_nodes",
            source_weight=0.78,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://check.torproject.org/torbulkexitlist"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch active Tor exit node IPs."""
        if self.offline_mode:
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            return self.get_mock_data()

        results: List[Dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for line in response.text.splitlines()[:500]:
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            results.append({
                "value": ip,
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 75.0,
                "reported_at": now_iso,
                "tags": ["tor", "anonymizer", "exit-node"],
                "reference_url": "https://check.torproject.org",
            })
        return results or self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Synthetic fallback indicators for testing and offline runs."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "185.220.101.5",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 78.0,
                "reported_at": now_iso,
                "tags": ["tor", "exit-node", "anonymization-network"],
                "reference_url": "https://check.torproject.org",
            },
            {
                "value": "185.220.102.8",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 78.0,
                "reported_at": now_iso,
                "tags": ["tor", "exit-node", "anonymization-network"],
                "reference_url": "https://check.torproject.org",
            },
        ]
