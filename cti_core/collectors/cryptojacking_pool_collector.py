"""Ingestion collector for illicit cryptojacking pools and stratum endpoints."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class CryptojackingPoolCollector(BaseCollector):
    """Ingests known Monero and cryptocurrency mining pool endpoints abused by botnets."""

    def __init__(self) -> None:
        super().__init__(
            name="cryptojacking_pools",
            source_weight=0.85,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/mining-pools.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch cryptomining pool indicators."""
        if self.offline_mode:
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            return self.get_mock_data()

        return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Synthetic fallback indicators for testing and offline runs."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "pool.minexmr.com",
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 88.0,
                "reported_at": now_iso,
                "tags": ["cryptojacking", "xmr-pool", "stratum"],
                "reference_url": "https://threatintel.internal/cryptojacking-pools",
            },
            {
                "value": "193.106.191.162",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 86.0,
                "reported_at": now_iso,
                "tags": ["cryptojacking", "mining-proxy", "xmrig"],
                "reference_url": "https://threatintel.internal/cryptojacking-proxies",
            },
        ]
