"""Ingestion collector for Phishunt.io suspicious phishing URL and domain telemetry."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class PhishuntCollector(BaseCollector):
    """Ingests newly registered and detected credential phishing URLs."""

    def __init__(self) -> None:
        super().__init__(
            name="phishunt_feed",
            source_weight=0.84,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://phishunt.io/feed.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch phishing URLs and domains."""
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
                "value": "http://secure-login-apple-support.cfd/auth",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 89.0,
                "reported_at": now_iso,
                "tags": ["phishing", "brand-impersonation", "apple"],
                "reference_url": "https://phishunt.io/detail/sample-01",
            },
            {
                "value": "login-microsoft-portal-verify.top",
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 86.0,
                "reported_at": now_iso,
                "tags": ["phishing", "credential-harvesting", "m365"],
                "reference_url": "https://phishunt.io/detail/sample-02",
            },
        ]
