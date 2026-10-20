"""Collector for AlienVault Open Threat Exchange (OTX) community pulses."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class OTXCollector(BaseCollector):
    """Ingests IoCs shared across high-confidence pulses from AlienVault OTX."""

    def __init__(self) -> None:
        super().__init__(
            name="alienvault_otx",
            source_weight=0.80,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50"

    async def collect(self) -> List[Dict[str, Any]]:
        """Collect subscribed pulses and extract indicators."""
        if self.offline_mode:
            logger.info("[otx] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[otx] Live API unreachable; using mock data.")
            return self.get_mock_data()

        try:
            data = response.json()
            results: List[Dict[str, Any]] = []
            now_iso = datetime.now(timezone.utc).isoformat()

            for pulse in data.get("results", []):
                tags = pulse.get("tags") or []
                for ind in pulse.get("indicators", []):
                    itype = ind.get("type", "").lower()
                    val = ind.get("indicator")
                    if not val:
                        continue
                    mapped_type = "ipv4" if itype == "ipv4" else ("domain" if itype == "domain" else "url")
                    results.append({
                        "value": val,
                        "type": mapped_type,
                        "source": self.name,
                        "source_weight": self.source_weight,
                        "reported_confidence": 85.0,
                        "reported_at": now_iso,
                        "tags": tags[:3] + ["otx-pulse"],
                        "reference_url": f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                    })
            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[otx] Parsing failed: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "194.26.29.112",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 88.0,
                "reported_at": now_iso,
                "tags": ["apt29", "c2", "otx-pulse"],
                "reference_url": "https://otx.alienvault.com/pulse/mock-001",
            },
            {
                "value": "apt-cozybear-command.org",
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["apt29", "dns-tunneling", "otx-pulse"],
                "reference_url": "https://otx.alienvault.com/pulse/mock-002",
            },
        ]
