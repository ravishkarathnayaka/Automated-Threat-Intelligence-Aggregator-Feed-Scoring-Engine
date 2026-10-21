"""Ingestion client for Dataplane protocol attack and scanner sensor feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class DataplaneCollector(BaseCollector):
    """Ingests malicious probing and brute-force IPs from Dataplane.org sensors."""

    def __init__(self) -> None:
        super().__init__(
            name="dataplane",
            source_weight=0.80,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://dataplane.org/sipinvitation.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch Dataplane protocol attacking IPs."""
        if self.offline_mode:
            logger.info("[dataplane] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[dataplane] Feed unreachable; using synthetic dataset.")
            return self.get_mock_data()

        try:
            results: List[Dict[str, Any]] = []
            now_iso = datetime.now(timezone.utc).isoformat()
            for line in response.text.splitlines()[:500]:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                parts = [p.strip() for p in raw.split("|")]
                if len(parts) < 3:
                    continue
                ip_str = parts[2]
                results.append({
                    "value": ip_str,
                    "type": "ipv4",
                    "source": self.name,
                    "source_weight": self.source_weight,
                    "reported_confidence": 82.0,
                    "reported_at": now_iso,
                    "tags": ["dataplane", "sip-scanner", "bruteforce"],
                    "reference_url": "https://dataplane.org",
                })
            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[dataplane] Parse failure: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "198.51.100.140",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["dataplane", "sip-scanner", "voip-attack"],
                "reference_url": "https://dataplane.org",
            },
            {
                "value": "198.51.100.141",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 80.0,
                "reported_at": now_iso,
                "tags": ["dataplane", "vnc-probe"],
                "reference_url": "https://dataplane.org",
            },
        ]
