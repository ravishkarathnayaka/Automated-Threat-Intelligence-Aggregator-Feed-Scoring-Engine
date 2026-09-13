"""Ingestion client for AbuseIPDB blacklist."""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class AbuseIPDBCollector(BaseCollector):
    """Collector for ingesting malicious IP addresses from AbuseIPDB Blacklist."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(
            name="abuseipdb",
            source_weight=0.85,
            rate_limit_per_second=1.0,
            max_retries=3,
        )
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self.endpoint = "https://api.abuseipdb.com/api/v2/blacklist"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch AbuseIPDB blacklist, gracefully falling back to synthetic mock data if no key or offline."""
        if self.offline_mode or not self.api_key or self.api_key.startswith("your_"):
            logger.info("[abuseipdb] Operating in offline/mock mode (no production API key supplied).")
            return self.get_mock_data()

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "confidenceMinimum": 80,
            "limit": 1000,
        }

        response = await self.fetch_with_retry(self.endpoint, headers=headers, params=params)
        if not response or response.status_code != 200:
            logger.warning("[abuseipdb] Live fetch failed or unauthenticated; falling back to synthetic feed.")
            return self.get_mock_data()

        try:
            payload = response.json()
            items = payload.get("data", [])
            results = []
            now_iso = datetime.now(timezone.utc).isoformat()
            for entry in items:
                ip = entry.get("ipAddress")
                if not ip:
                    continue
                score = entry.get("abuseConfidenceScore", 80)
                results.append(
                    {
                        "value": ip,
                        "type": "ipv4" if ":" not in ip else "ipv6",
                        "source": self.name,
                        "source_weight": self.source_weight,
                        "reported_confidence": float(score),
                        "reported_at": entry.get("lastReportedAt", now_iso),
                        "tags": ["abuseipdb-blacklist", "scanner", "brute-force"],
                        "reference_url": f"https://www.abuseipdb.com/check/{ip}",
                        "raw_metadata": entry,
                    }
                )
            return results
        except Exception as exc:
            logger.error("[abuseipdb] Failed to parse response: %s; falling back to mock.", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Return synthetic AbuseIPDB blacklist indicators."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "185.220.101.5",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 100.0,
                "reported_at": now_iso,
                "tags": ["tor-exit", "brute-force", "ssh-scan"],
                "reference_url": "https://www.abuseipdb.com/check/185.220.101.5",
                "raw_metadata": {"country": "DE", "totalReports": 420},
            },
            {
                "value": "45.143.203.2",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 98.0,
                "reported_at": now_iso,
                "tags": ["mirai", "scanner", "telnet-bruteforce"],
                "reference_url": "https://www.abuseipdb.com/check/45.143.203.2",
                "raw_metadata": {"country": "RU", "totalReports": 312},
            },
            {
                "value": "194.26.29.112",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 92.0,
                "reported_at": now_iso,
                "tags": ["cobalt-strike", "c2", "web-exploit"],
                "reference_url": "https://www.abuseipdb.com/check/194.26.29.112",
                "raw_metadata": {"country": "NL", "totalReports": 185},
            },
            {
                "value": "2a02:4780:1:78::1",
                "type": "ipv6",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 88.0,
                "reported_at": now_iso,
                "tags": ["ddos", "scanner"],
                "reference_url": "https://www.abuseipdb.com/check/2a02:4780:1:78::1",
                "raw_metadata": {"country": "FR", "totalReports": 95},
            },
        ]
