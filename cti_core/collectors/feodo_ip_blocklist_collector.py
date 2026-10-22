"""Ingestion collector for Feodo Tracker aggressive C2 IP blocklist."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class FeodoIPBlocklistCollector(BaseCollector):
    """Ingests confirmed aggressive botnet C2 IPs (Emotet, Dridex, Qakbot) from Feodo Tracker."""

    def __init__(self) -> None:
        super().__init__(
            name="feodo_ip_blocklist",
            source_weight=0.95,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch aggressive botnet IPs."""
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
                "reported_confidence": 95.0,
                "reported_at": now_iso,
                "tags": ["botnet-c2", "feodo", "aggressive-blocklist"],
                "reference_url": "https://feodotracker.abuse.ch",
            })
        return results

    def get_mock_data(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "185.220.101.5",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 95.0,
                "reported_at": now_iso,
                "tags": ["botnet-c2", "feodo", "aggressive-blocklist"],
                "reference_url": "https://feodotracker.abuse.ch",
            }
        ]
