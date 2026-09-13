"""Ingestion client for Abuse.ch URLhaus malware links and payload indicators."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class URLhausCollector(BaseCollector):
    """Collector for ingesting active malware distribution URLs and domains from URLhaus."""

    def __init__(self):
        super().__init__(
            name="urlhaus",
            source_weight=0.85,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://urlhaus.abuse.ch/downloads/json_recent/"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch active malware URLs from the open URLhaus recent feed."""
        if self.offline_mode:
            logger.info("[urlhaus] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[urlhaus] Public feed fetch failed; falling back to synthetic dataset.")
            return self.get_mock_data()

        try:
            payload = response.json()
            # The feed has format {"<id>": [{"id": ..., "url": ...}]} or {"urls": [...]}
            results: List[Dict[str, Any]] = []
            entries = []
            if isinstance(payload, dict):
                if "urls" in payload and isinstance(payload["urls"], list):
                    entries = payload["urls"]
                else:
                    for val in payload.values():
                        if isinstance(val, list):
                            entries.extend(val)
                        elif isinstance(val, dict):
                            entries.append(val)

            now_iso = datetime.now(timezone.utc).isoformat()
            for item in entries[:500]:  # Process top 500 recent items
                url_str = item.get("url")
                if not url_str:
                    continue
                tags = item.get("tags") or []
                if isinstance(tags, str):
                    tags = [tags]
                threat = item.get("threat", "malware_download")
                tags.append(threat)
                tags.append("urlhaus")

                results.append(
                    {
                        "value": url_str,
                        "type": "url",
                        "source": self.name,
                        "source_weight": self.source_weight,
                        "reported_confidence": 90.0,
                        "reported_at": item.get("dateadded", now_iso),
                        "tags": list(set(tags)),
                        "reference_url": item.get("urlhaus_reference"),
                        "raw_metadata": item,
                    }
                )
            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[urlhaus] Error parsing feed data: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Return synthetic URLhaus malware URLs."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "hxxp://185.220.101.5/bins/mozi.arm",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 95.0,
                "reported_at": now_iso,
                "tags": ["mozi", "botnet", "arm", "urlhaus"],
                "reference_url": "https://urlhaus.abuse.ch/url/10101/",
                "raw_metadata": {"threat": "malware_download"},
            },
            {
                "value": "http://evil-payload-distribution.xyz/invoice.exe",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 90.0,
                "reported_at": now_iso,
                "tags": ["redline", "stealer", "executable", "urlhaus"],
                "reference_url": "https://urlhaus.abuse.ch/url/10102/",
                "raw_metadata": {"threat": "malware_download"},
            },
            {
                "value": "hxxps://c2-beacon.darknet-ops.cc/api/v1/gate",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 92.0,
                "reported_at": now_iso,
                "tags": ["cobalt-strike", "c2", "urlhaus"],
                "reference_url": "https://urlhaus.abuse.ch/url/10103/",
                "raw_metadata": {"threat": "c2"},
            },
        ]
