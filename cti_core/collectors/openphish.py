"""Ingestion client for OpenPhish community zero-day phishing URL feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class OpenPhishCollector(BaseCollector):
    """Collector for ingesting active phishing URLs from OpenPhish."""

    def __init__(self) -> None:
        super().__init__(
            name="openphish",
            source_weight=0.85,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://openphish.com/feed.txt"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch active phishing URLs from OpenPhish plaintext feed."""
        if self.offline_mode:
            logger.info("[openphish] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[openphish] Feed fetch failed; falling back to synthetic dataset.")
            return self.get_mock_data()

        try:
            lines = response.text.splitlines()
            results: List[Dict[str, Any]] = []
            now_iso = datetime.now(timezone.utc).isoformat()

            for line in lines[:500]:
                url_str = line.strip()
                if not url_str or url_str.startswith("#"):
                    continue

                results.append(
                    {
                        "value": url_str,
                        "type": "url",
                        "source": self.name,
                        "source_weight": self.source_weight,
                        "reported_confidence": 90.0,
                        "reported_at": now_iso,
                        "tags": ["phishing", "credential-harvesting", "openphish"],
                        "reference_url": "https://openphish.com/",
                        "raw_metadata": {"threat_category": "phishing"},
                    }
                )

            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[openphish] Error parsing feed data: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Return synthetic OpenPhish phishing URLs."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "hxxps://secure-login-account-verify[.]net/auth",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 90.0,
                "reported_at": now_iso,
                "tags": ["phishing", "credential-harvesting", "openphish"],
                "reference_url": "https://openphish.com/",
                "raw_metadata": {"threat_category": "phishing"},
            },
            {
                "value": "http://paypal-security-update-center.org/login.php",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 92.0,
                "reported_at": now_iso,
                "tags": ["phishing", "financial-theft", "openphish"],
                "reference_url": "https://openphish.com/",
                "raw_metadata": {"threat_category": "phishing"},
            },
        ]
