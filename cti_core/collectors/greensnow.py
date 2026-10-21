"""Ingestion client for GreenSnow automated attack IP blocklist."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class GreenSnowCollector(BaseCollector):
    """Ingests malicious attacking IPs reported by GreenSnow global sensors."""

    def __init__(self) -> None:
        super().__init__(
            name="greensnow",
            source_weight=0.80,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://greensnow.co/greensnow.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch GreenSnow attack IP feed."""
        if self.offline_mode:
            logger.info("[greensnow] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[greensnow] Feed unreachable; using synthetic dataset.")
            return self.get_mock_data()

        try:
            results: List[Dict[str, Any]] = []
            now_iso = datetime.now(timezone.utc).isoformat()
            for line in response.text.splitlines()[:500]:
                ip_str = line.strip()
                if not ip_str or ip_str.startswith("#"):
                    continue
                results.append({
                    "value": ip_str,
                    "type": "ipv4",
                    "source": self.name,
                    "source_weight": self.source_weight,
                    "reported_confidence": 85.0,
                    "reported_at": now_iso,
                    "tags": ["greensnow", "bruteforce", "exploit-attempt"],
                    "reference_url": "https://greensnow.co",
                })
            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[greensnow] Parsing failed: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "198.51.100.125",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["greensnow", "bruteforce", "ssh-scan"],
                "reference_url": "https://greensnow.co",
            },
            {
                "value": "198.51.100.126",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["greensnow", "port-scanner"],
                "reference_url": "https://greensnow.co",
            },
        ]
