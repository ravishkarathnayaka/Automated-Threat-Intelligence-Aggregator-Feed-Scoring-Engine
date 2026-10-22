"""Ingestion collector for Rutgers and academic network bad hosts scanning feeds."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class RutgersBadHostsCollector(BaseCollector):
    """Ingests persistent academic network scan and brute-force IP addresses."""

    def __init__(self) -> None:
        super().__init__(
            name="rutgers_bad_hosts",
            source_weight=0.75,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/rutgers_badhosts.ipset"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch scanned IPs from badhosts feed."""
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
                "tags": ["brute-force", "ssh-scanner", "bad-host"],
                "reference_url": "https://iplists.firehol.org",
            })
        return results

    def get_mock_data(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "194.26.29.112",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 75.0,
                "reported_at": now_iso,
                "tags": ["brute-force", "ssh-scanner", "bad-host"],
                "reference_url": "https://iplists.firehol.org",
            }
        ]
