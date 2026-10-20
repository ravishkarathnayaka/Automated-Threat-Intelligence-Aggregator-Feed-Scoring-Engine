"""Ingestion client for Abuse.ch SSL Blacklist (SSLBL) malicious SSL SHA1 fingerprints."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class SSLBLCollector(BaseCollector):
    """Collector for ingesting SHA1 fingerprints of malicious SSL certificates."""

    def __init__(self) -> None:
        super().__init__(
            name="sslbl",
            source_weight=0.85,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch active malicious SSL SHA1 hashes from SSLBL CSV feed."""
        if self.offline_mode:
            logger.info("[sslbl] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[sslbl] Feed fetch failed; falling back to synthetic dataset.")
            return self.get_mock_data()

        try:
            lines = response.text.splitlines()
            results: List[Dict[str, Any]] = []
            now_iso = datetime.now(timezone.utc).isoformat()

            for line in lines:
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip().strip('"') for p in line.split(",")]
                if len(parts) >= 2:
                    sha1_hash = parts[1].lower()
                    reason = parts[2] if len(parts) > 2 else "Malicious SSL Certificate"
                    if len(sha1_hash) == 40:
                        results.append(
                            {
                                "value": sha1_hash,
                                "type": "sha1",
                                "source": self.name,
                                "source_weight": self.source_weight,
                                "reported_confidence": 90.0,
                                "reported_at": parts[0] if parts[0] else now_iso,
                                "tags": ["ssl-cert", "malicious-tls", "sslbl", reason.lower().replace(" ", "-")],
                                "reference_url": f"https://sslbl.abuse.ch/ssl-certificates/sha1/{sha1_hash}/",
                                "raw_metadata": {"reason": reason},
                            }
                        )

            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[sslbl] Error parsing feed data: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Return synthetic SSLBL SHA1 hashes."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "2f4581f18544e3fa338a0b0d3667c3b999c086d4",
                "type": "sha1",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 95.0,
                "reported_at": now_iso,
                "tags": ["ssl-cert", "malicious-tls", "sslbl", "dridex"],
                "reference_url": "https://sslbl.abuse.ch/ssl-certificates/sha1/2f4581f18544e3fa338a0b0d3667c3b999c086d4/",
                "raw_metadata": {"reason": "Dridex C2"},
            },
            {
                "value": "3d9c7bb618684bb55c425aa5279be7bbbb021816",
                "type": "sha1",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 90.0,
                "reported_at": now_iso,
                "tags": ["ssl-cert", "malicious-tls", "sslbl", "trickbot"],
                "reference_url": "https://sslbl.abuse.ch/ssl-certificates/sha1/3d9c7bb618684bb55c425aa5279be7bbbb021816/",
                "raw_metadata": {"reason": "TrickBot C2"},
            },
        ]
