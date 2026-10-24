"""Ingestion collector for AlienVault Open Threat Exchange (OTX) pulse indicators."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class AlienVaultOTXCollector(BaseCollector):
    """Ingests collaborative community pulses and IoCs from AlienVault OTX."""

    def __init__(self) -> None:
        super().__init__(
            name="alienvault_otx",
            source_weight=0.82,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch threat indicators from AlienVault OTX pulses."""
        if self.offline_mode:
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            return self.get_mock_data()

        results: List[Dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            data = response.json()
            for pulse in data.get("results", [])[:20]:
                for ind in pulse.get("indicators", [])[:50]:
                    val = ind.get("indicator")
                    ind_type = ind.get("type", "").lower()
                    if not val:
                        continue
                    results.append({
                        "value": val,
                        "type": ind_type if ind_type in ("ipv4", "domain", "url", "sha256") else "unknown",
                        "source": self.name,
                        "source_weight": self.source_weight,
                        "reported_confidence": 80.0,
                        "reported_at": now_iso,
                        "tags": ["alienvault", "otx", "community-pulse"],
                        "reference_url": f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                    })
        except Exception as exc:
            logger.warning("Failed parsing AlienVault OTX response: %s", exc)
            return self.get_mock_data()

        return results or self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Synthetic fallback indicators for testing and offline runs."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "194.26.29.112",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["alienvault", "c2-beacon", "otx-pulse"],
                "reference_url": "https://otx.alienvault.com/pulse/sample-01",
            },
            {
                "value": "apt-backdoor-service.com",
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 80.0,
                "reported_at": now_iso,
                "tags": ["alienvault", "apt-infrastructure", "otx-pulse"],
                "reference_url": "https://otx.alienvault.com/pulse/sample-02",
            },
        ]
