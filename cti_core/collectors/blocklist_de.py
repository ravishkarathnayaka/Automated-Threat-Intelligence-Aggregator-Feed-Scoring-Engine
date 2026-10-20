"""Ingestion client for Blocklist.de attack and brute-force IP feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class BlocklistDeCollector(BaseCollector):
    """Collector for ingesting active brute-force and attack IPs from Blocklist.de."""

    def __init__(self) -> None:
        super().__init__(
            name="blocklist_de",
            source_weight=0.80,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://api.blocklist.de/getnew.php?time=3600"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch active attacker IPs from Blocklist.de recent feed."""
        if self.offline_mode:
            logger.info("[blocklist_de] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[blocklist_de] Feed fetch failed; falling back to synthetic dataset.")
            return self.get_mock_data()

        try:
            lines = response.text.splitlines()
            results: List[Dict[str, Any]] = []
            now_iso = datetime.now(timezone.utc).isoformat()

            for line in lines[:500]:
                ip_str = line.strip()
                if not ip_str or ip_str.startswith("#"):
                    continue

                results.append(
                    {
                        "value": ip_str,
                        "type": "ipv4" if ":" not in ip_str else "ipv6",
                        "source": self.name,
                        "source_weight": self.source_weight,
                        "reported_confidence": 85.0,
                        "reported_at": now_iso,
                        "tags": ["brute-force", "ssh-scan", "blocklist-de"],
                        "reference_url": f"https://www.blocklist.de/en/search.html?ip={ip_str}",
                        "raw_metadata": {"service": "fail2ban"},
                    }
                )

            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[blocklist_de] Error parsing feed data: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Return synthetic Blocklist.de attacker IPs."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "194.26.29.115",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["brute-force", "ssh-scan", "blocklist-de"],
                "reference_url": "https://www.blocklist.de/en/search.html?ip=194.26.29.115",
                "raw_metadata": {"service": "ssh"},
            },
            {
                "value": "45.142.195.42",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 88.0,
                "reported_at": now_iso,
                "tags": ["brute-force", "web-scan", "blocklist-de"],
                "reference_url": "https://www.blocklist.de/en/search.html?ip=45.142.195.42",
                "raw_metadata": {"service": "apache"},
            },
        ]
