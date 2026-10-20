"""Ingestion client for Abuse.ch ThreatFox multi-type malware IoC feed."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class ThreatFoxCollector(BaseCollector):
    """Collector for ingesting multi-type malware indicators from ThreatFox."""

    def __init__(self) -> None:
        super().__init__(
            name="threatfox",
            source_weight=0.85,
            rate_limit_per_second=2.0,
            max_retries=3,
        )
        self.endpoint = "https://threatfox.abuse.ch/export/json/recent/"

    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch active indicators from ThreatFox recent JSON feed."""
        if self.offline_mode:
            logger.info("[threatfox] Operating in offline mode; using mock data.")
            return self.get_mock_data()

        response = await self.fetch_with_retry(self.endpoint)
        if not response or response.status_code != 200:
            logger.warning("[threatfox] Feed fetch failed; falling back to synthetic dataset.")
            return self.get_mock_data()

        try:
            data = response.json()
            entries: List[Dict[str, Any]] = []
            if isinstance(data, dict):
                for val in data.values():
                    if isinstance(val, list):
                        entries.extend(val)
                    elif isinstance(val, dict):
                        entries.append(val)

            results: List[Dict[str, Any]] = []
            now_iso = datetime.now(timezone.utc).isoformat()

            for item in entries[:500]:
                val = item.get("ioc_value")
                if not val:
                    continue

                raw_type = item.get("ioc_type", "domain").lower()
                threat_type = item.get("threat_type", "botnet_cc").lower()
                malware = item.get("malware_printable", "unknown_malware").lower()

                # Map ThreatFox types to standard types
                if "ip:port" in raw_type or "ip" in raw_type:
                    t = "ipv4" if ":" not in val.split(":")[0] else "ipv6"
                    clean_val = val.split(":")[0]
                elif "domain" in raw_type:
                    t = "domain"
                    clean_val = val
                elif "url" in raw_type:
                    t = "url"
                    clean_val = val
                elif "hash" in raw_type or "sha256" in raw_type:
                    t = "sha256"
                    clean_val = val
                else:
                    t = "domain"
                    clean_val = val

                confidence = float(item.get("confidence_level", 85.0))
                tags = [malware, threat_type, "threatfox"]

                results.append(
                    {
                        "value": clean_val,
                        "type": t,
                        "source": self.name,
                        "source_weight": self.source_weight,
                        "reported_confidence": confidence,
                        "reported_at": item.get("first_seen_utc", now_iso),
                        "tags": list(set(tags)),
                        "reference_url": f"https://threatfox.abuse.ch/ioc/{item.get('id', '')}/",
                        "raw_metadata": item,
                    }
                )

            return results if results else self.get_mock_data()
        except Exception as exc:
            logger.error("[threatfox] Error parsing feed data: %s", exc)
            return self.get_mock_data()

    def get_mock_data(self) -> List[Dict[str, Any]]:
        """Return synthetic ThreatFox indicators."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "value": "185.220.101.7",
                "type": "ipv4",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 90.0,
                "reported_at": now_iso,
                "tags": ["cobalt-strike", "c2", "threatfox"],
                "reference_url": "https://threatfox.abuse.ch/ioc/1001/",
                "raw_metadata": {"threat_type": "botnet_cc", "malware": "Cobalt Strike"},
            },
            {
                "value": "darknet-command-server.cc",
                "type": "domain",
                "source": self.name,
                "source_weight": self.source_weight,
                "reported_confidence": 85.0,
                "reported_at": now_iso,
                "tags": ["redline-stealer", "c2", "threatfox"],
                "reference_url": "https://threatfox.abuse.ch/ioc/1002/",
                "raw_metadata": {"threat_type": "botnet_cc", "malware": "RedLine"},
            },
        ]
