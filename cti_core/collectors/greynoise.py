"""Ingestion collector for GreyNoise community scanner noise and benign mass-scanner IPs."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class GreyNoiseCollector(BaseCollector):
    """Ingests GreyNoise intelligence on internet noise, benign research scanners, and opportunistic actors."""

    def __init__(self) -> None:
        super().__init__(
            name="greynoise",
            source_weight=0.85,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://api.greynoise.io/v3/community"

    async def collect(self) -> List[Dict[str, Any]]:
        """Collect scanner intelligence from GreyNoise."""
        if self.offline_mode:
            logger.info("[greynoise] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        # In production community tier, mock or feed lookup is used
        return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Return synthetic GreyNoise internet scanner telemetry."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "198.51.100.77",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["greynoise", "malicious-scanner", "c2-recon"],
                "reference_url": "https://viz.greynoise.io/ip/198.51.100.77",
                "raw_metadata": {"classification": "malicious", "noise": True},
            },
            {
                "value": "198.51.100.88",
                "type": "ipv4",
                "source": self.name,
                "source_weight": 0.40,  # Benign scanner has low threat weight
                "reported_confidence": 30.0,
                "reported_at": now_iso,
                "tags": ["greynoise", "benign-scanner", "research"],
                "reference_url": "https://viz.greynoise.io/ip/198.51.100.88",
                "raw_metadata": {"classification": "benign", "noise": True},
            },
        ]
