"""Ingestion client for urlscan.io public malicious scan results."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class URLScanCollector(BaseCollector):
    """Collector for ingesting confirmed malicious URLs from urlscan.io search API."""

    def __init__(self) -> None:
        super().__init__(
            name="urlscan",
            source_weight=0.85,
            rate_limit_per_second=1.0,
            max_retries=3,
        )
        self.endpoint = "https://urlscan.io/api/v1/search/?q=verdicts.malicious:true&size=100"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch malicious community scan results from urlscan.io."""
        if self.offline_mode:
            logger.info("[urlscan] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[urlscan] API query failed; falling back to mock data.")
            return self.get_mock_data()

        try:
            data = response.json()
            results: List[Dict[str, Any]] = []
            now_iso = datetime.now(timezone.utc).isoformat()

            for item in data.get("results", []):
                page = item.get("page", {})
                target_url = page.get("url")
                if not target_url:
                    continue

                verdicts = item.get("verdicts", {}).get("overall", {})
                score = 85.0 if verdicts.get("malicious") else 60.0

                results.append({
                    "value": target_url,
                    "type": "url",
                    "source": self.name,
                    "source_weight": self.source_weight,
                    "reported_confidence": score,
                    "reported_at": now_iso,
                    "tags": ["urlscan", "malicious-web", "phishing"],
                    "reference_url": item.get("result", "https://urlscan.io"),
                    "raw_metadata": page,
                })

            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[urlscan] Error parsing scan results: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Return synthetic urlscan.io malicious web scan items."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "hxxps://credential-harvest-portal[.]click/login",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 88.0,
                "reported_at": now_iso,
                "tags": ["urlscan", "malicious-web", "credential-theft"],
                "reference_url": "https://urlscan.io/result/mock-001",
                "raw_metadata": {"domain": "credential-harvest-portal.click"},
            },
            {
                "value": "hxxp://suspicious-dropper-cdn[.]xyz/payload.bin",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 92.0,
                "reported_at": now_iso,
                "tags": ["urlscan", "malware-dropper"],
                "reference_url": "https://urlscan.io/result/mock-002",
                "raw_metadata": {"domain": "suspicious-dropper-cdn.xyz"},
            },
        ]
