"""Ingestion collector for Bambenek Consulting C2 and DGA domain feeds."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class BambenekC2Collector(BaseCollector):
    """Ingests confirmed C2 domain indicators from Bambenek Consulting feeds."""

    def __init__(self) -> None:
        super().__init__(
            name="bambenek_c2",
            source_weight=0.85,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch C2 domains from Bambenek feed."""
        if self.offline_mode:
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            return self.get_mock_data()

        results: List[Dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for line in response.text.splitlines()[:500]:
            parts = line.strip().split(",")
            dom = parts[0].strip() if parts else ""
            if not dom or dom.startswith("#"):
                continue
            family = parts[1].strip() if len(parts) > 1 else "generic-c2"
            results.append({
                "value": dom,
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 90.0,
                "reported_at": now_iso,
                "tags": ["c2", "bambenek", family.lower().replace(" ", "-")],
                "reference_url": "https://osint.bambenekconsulting.com",
            })
        return results

    def get_mock_data(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "apt-c2-beacon.dynv6.net",
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 90.0,
                "reported_at": now_iso,
                "tags": ["c2", "bambenek", "qakbot"],
                "reference_url": "https://osint.bambenekconsulting.com",
            }
        ]
