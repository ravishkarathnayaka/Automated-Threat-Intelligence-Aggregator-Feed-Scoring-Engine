"""Ingestion collector for ThreatView.io high-confidence Cobalt Strike IP feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class ThreatViewIOCollector(BaseCollector):
    """Ingests verified Cobalt Strike teamserver and C2 IPs from ThreatView.io."""

    def __init__(self) -> None:
        super().__init__(
            name="threatview_io",
            source_weight=0.90,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://threatview.io/Downloads/HIGH-Confidence-CobaltStrike-US-Blocklist.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch Cobalt Strike IPs."""
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
                "reported_confidence": 92.0,
                "reported_at": now_iso,
                "tags": ["cobalt-strike", "c2", "teamserver", "threatview"],
                "reference_url": "https://threatview.io",
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
                "reported_confidence": 92.0,
                "reported_at": now_iso,
                "tags": ["cobalt-strike", "c2", "teamserver", "threatview"],
                "reference_url": "https://threatview.io",
            }
        ]
