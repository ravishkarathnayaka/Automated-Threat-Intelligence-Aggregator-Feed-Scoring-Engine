"""Ingestion collector for Abuse.ch SSL Blacklist botnet C2 IP:Port feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class SSLBLBotnetCollector(BaseCollector):
    """Ingests active botnet C2 IP:port endpoints from Abuse.ch SSL Blacklist."""

    def __init__(self) -> None:
        super().__init__(
            name="sslbl_botnet",
            source_weight=0.90,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch active botnet IP endpoints."""
        if self.offline_mode:
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            return self.get_mock_data()

        results: List[Dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for line in response.text.splitlines()[:500]:
            parts = line.strip().split(",")
            ip = parts[0].strip() if parts else ""
            if not ip or ip.startswith("#") or ip.lower().startswith("dst_ip"):
                continue
            port = parts[1].strip() if len(parts) > 1 else ""
            results.append({
                "value": ip,
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 92.0,
                "reported_at": now_iso,
                "tags": ["ssl-c2", "sslbl", "botnet", f"port-{port}" if port else "encrypted-c2"],
                "reference_url": "https://sslbl.abuse.ch",
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
                "reported_confidence": 92.0,
                "reported_at": now_iso,
                "tags": ["ssl-c2", "sslbl", "botnet", "port-443"],
                "reference_url": "https://sslbl.abuse.ch",
            }
        ]
