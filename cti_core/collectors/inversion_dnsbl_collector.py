"""Inversion DNSBL and spam IP blocklist collector."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class InversionDNSBLCollector(BaseCollector):
    """Ingests malicious spamming and automated attack IPs from DNSBL zone feed."""

    def __init__(self) -> None:
        super().__init__(
            name="inversion_dnsbl",
            source_weight=0.75,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch active attacking IPs."""
        if self.offline_mode:
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            return self.get_mock_data()

        results: List[Dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for line in response.text.splitlines()[:500]:
            ip_str = line.strip().split()[0] if line.strip() else ""
            if not ip_str or ip_str.startswith("#"):
                continue
            results.append({
                "value": ip_str,
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 80.0,
                "reported_at": now_iso,
                "tags": ["dnsbl", "spam-source", "automated-scanner"],
                "reference_url": "https://github.com/stamparm/ipsum",
            })
        return results

    def get_mock_data(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "185.196.8.24",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 80.0,
                "reported_at": now_iso,
                "tags": ["dnsbl", "spam-source", "automated-scanner"],
                "reference_url": "https://github.com/stamparm/ipsum",
            }
        ]
