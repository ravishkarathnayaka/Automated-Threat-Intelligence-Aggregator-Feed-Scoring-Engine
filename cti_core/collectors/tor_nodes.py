"""Ingestion client for official Tor Project exit node IP addresses."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class TorExitNodesCollector(BaseCollector):
    """Collector for ingesting active Tor exit relay IP addresses."""

    def __init__(self) -> None:
        super().__init__(
            name="tor_exit_nodes",
            source_weight=0.75,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://check.torproject.org/torbulkexitlist"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch active Tor exit node IP addresses."""
        if self.offline_mode:
            logger.info("[tor_exit_nodes] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[tor_exit_nodes] Feed fetch failed; falling back to synthetic dataset.")
            return self.get_mock_data()

        try:
            lines = response.text.splitlines()
            results: List[Dict[str, Any]] = []
            now_iso = datetime.now(timezone.utc).isoformat()

            for line in lines:
                ip = line.strip()
                if not ip or ip.startswith("#"):
                    continue

                results.append(
                    {
                        "value": ip,
                        "type": "ipv4" if ":" not in ip else "ipv6",
                        "source": self.name,
                        "source_weight": self.source_weight,
                        "reported_confidence": 85.0,
                        "reported_at": now_iso,
                        "tags": ["tor", "tor-exit", "anonymizer"],
                        "reference_url": "https://metrics.torproject.org/",
                        "raw_metadata": {"protocol": "tor"},
                    }
                )

            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[tor_exit_nodes] Error parsing feed data: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Return synthetic Tor exit nodes."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "185.220.101.5",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 90.0,
                "reported_at": now_iso,
                "tags": ["tor", "tor-exit", "anonymizer"],
                "reference_url": "https://metrics.torproject.org/",
                "raw_metadata": {"protocol": "tor"},
            },
            {
                "value": "171.25.193.20",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["tor", "tor-exit", "anonymizer"],
                "reference_url": "https://metrics.torproject.org/",
                "raw_metadata": {"protocol": "tor"},
            },
        ]
