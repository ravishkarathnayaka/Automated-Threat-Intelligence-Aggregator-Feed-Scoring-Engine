"""Ingestion client for CINS Army malicious IP blacklist feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class CINSArmyCollector(BaseCollector):
    """Ingests malicious IP addresses flagged by CINS Army threat sensors."""

    def __init__(self) -> None:
        super().__init__(
            name="cins_army",
            source_weight=0.85,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "http://cinsscore.com/list/ci-badguys.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch bad reputation IP list from CINS Army."""
        if self.offline_mode:
            logger.info("[cins_army] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[cins_army] Feed unreachable; using synthetic dataset.")
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
                    "reported_confidence": 88.0,
                    "reported_at": now_iso,
                    "tags": ["cins-army", "malicious-ip", "scanner"],
                    "reference_url": "http://cinsscore.com",
                })
            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[cins_army] Error parsing feed: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "198.51.100.110",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 88.0,
                "reported_at": now_iso,
                "tags": ["cins-army", "malicious-ip", "attacker"],
                "reference_url": "http://cinsscore.com",
            },
            {
                "value": "198.51.100.111",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["cins-army", "bruteforce"],
                "reference_url": "http://cinsscore.com",
            },
        ]
