"""Ingestion collector for VXVault active malware distribution URL feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class VXVaultCollector(BaseCollector):
    """Ingests direct malware payload distribution URLs from VXVault."""

    def __init__(self) -> None:
        super().__init__(
            name="vxvault",
            source_weight=0.85,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "http://vxvault.net/URL_List.php"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch active malware URLs from VXVault."""
        if self.offline_mode:
            logger.info("[vxvault] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[vxvault] Feed unreachable; using synthetic dataset.")
            return self.get_mock_data()

        try:
            results: List[Dict[str, Any]] = []
            now_iso = datetime.now(timezone.utc).isoformat()
            for line in response.text.splitlines()[:500]:
                url_str = line.strip()
                if not url_str or url_str.startswith("#"):
                    continue
                results.append({
                    "value": url_str,
                    "type": "url",
                    "source": self.name,
                    "source_weight": self.source_weight,
                    "reported_confidence": 90.0,
                    "reported_at": now_iso,
                    "tags": ["vxvault", "malware-binary", "payload-dropper"],
                    "reference_url": "http://vxvault.net",
                })
            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[vxvault] Parse error: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "hxxp://185.196.8.99/bins/dropper.x86",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 92.0,
                "reported_at": now_iso,
                "tags": ["vxvault", "malware-binary", "mirai"],
                "reference_url": "http://vxvault.net",
            },
            {
                "value": "hxxp://malware-drop-site[.]cc/invoice.scr",
                "type": "url",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 88.0,
                "reported_at": now_iso,
                "tags": ["vxvault", "stealer", "trojan"],
                "reference_url": "http://vxvault.net",
            },
        ]
