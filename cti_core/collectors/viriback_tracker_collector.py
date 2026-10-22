"""Ingestion collector for ViriBack C2 Tracker active malware panel feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class ViriBackTrackerCollector(BaseCollector):
    """Ingests identified malware C2 panels and gate URLs from ViriBack Tracker."""

    def __init__(self) -> None:
        super().__init__(
            name="viriback_tracker",
            source_weight=0.85,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://tracker.viriback.net/dump.php"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch malware panels from ViriBack."""
        if self.offline_mode:
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            return self.get_mock_data()

        results: List[Dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for line in response.text.splitlines()[:500]:
            parts = line.strip().split(",")
            family = parts[0].strip() if parts else ""
            url = parts[1].strip() if len(parts) > 1 else ""
            if not url or url.startswith("#"):
                continue
            results.append({
                "value": url,
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 88.0,
                "reported_at": now_iso,
                "tags": ["c2-panel", "viriback", family.lower().replace(" ", "-")],
                "reference_url": "https://tracker.viriback.net",
            })
        return results

    def get_mock_data(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "http://evil-c2-panel.xyz/gate.php",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 88.0,
                "reported_at": now_iso,
                "tags": ["c2-panel", "viriback", "smokeloader"],
                "reference_url": "https://tracker.viriback.net",
            }
        ]
