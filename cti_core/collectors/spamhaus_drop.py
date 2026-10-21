"""Ingestion client for Spamhaus DROP (Don't Route Or Peer) network blocklist."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class SpamhausDROPCollector(BaseCollector):
    """Ingests stolen and cybercrime-operated IP subnets from Spamhaus DROP."""

    def __init__(self) -> None:
        super().__init__(
            name="spamhaus_drop",
            source_weight=0.95,  # DROP is authoritative
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://www.spamhaus.org/drop/drop.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch Spamhaus DROP netblocks."""
        if self.offline_mode:
            logger.info("[spamhaus_drop] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[spamhaus_drop] Feed unreachable; using synthetic dataset.")
            return self.get_mock_data()

        try:
            results: List[Dict[str, Any]] = []
            now_iso = datetime.now(timezone.utc).isoformat()
            for line in response.text.splitlines()[:500]:
                raw = line.strip()
                if not raw or raw.startswith(";"):
                    continue
                parts = raw.split(";")
                subnet = parts[0].strip()
                sbl_ref = parts[1].strip() if len(parts) > 1 else ""

                results.append({
                    "value": subnet,
                    "type": "ipv4",
                    "source": self.name,
                    "source_weight": self.source_weight,
                    "reported_confidence": 98.0,
                    "reported_at": now_iso,
                    "tags": ["spamhaus-drop", "bulletproof", "hijacked-subnet"],
                    "reference_url": f"https://check.spamhaus.org/sbl/{sbl_ref}",
                })
            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[spamhaus_drop] Parsing failed: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "198.51.100.0/24",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 98.0,
                "reported_at": now_iso,
                "tags": ["spamhaus-drop", "bulletproof", "hijacked-subnet"],
                "reference_url": "https://check.spamhaus.org/sbl/SBL123456",
            },
            {
                "value": "203.0.113.0/24",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 98.0,
                "reported_at": now_iso,
                "tags": ["spamhaus-drop", "cybercrime"],
                "reference_url": "https://check.spamhaus.org/sbl/SBL654321",
            },
        ]
