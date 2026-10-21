"""VMware Carbon Black Cloud threat intelligence watchlist exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class CarbonBlackExporter:
    """Exports indicators into VMware Carbon Black Cloud Enterprise EDR feed/watchlist format."""

    @classmethod
    def export_watchlist(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        name: str = "Sentinel-CTI-Watchlist",
        min_score: float = 75.0,
    ) -> Dict[str, Any]:
        """Generate Carbon Black Cloud feed schema dictionary."""
        ips: List[str] = []
        hashes: List[str] = []
        domains: List[str] = []

        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                ioc_type = item.get("type", "").lower()
                score = float(item.get("confidence_score", 0.0))
                is_whitelisted = item.get("is_whitelisted", False)
            elif isinstance(item, IndicatorRead):
                norm_val = item.normalized_value
                ioc_type = item.type.value.lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
            else:
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type).lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)

            if is_whitelisted or score < min_score:
                continue

            if ioc_type in ("ipv4", "ipv6") and norm_val not in ips:
                ips.append(norm_val)
            elif ioc_type in ("md5", "sha256") and norm_val not in hashes:
                hashes.append(norm_val)
            elif ioc_type == "domain" and norm_val not in domains:
                domains.append(norm_val)

        return {
            "feedinfo": {
                "name": name,
                "display_name": "SENTINEL-CTI Active Threat Watchlist",
                "provider_url": "https://sentinel-cti.local",
                "summary": "Real-time scored adversary indicators",
                "category": "ThreatIntelligence",
            },
            "reports": [
                {
                    "id": f"{name}-report-001",
                    "title": "High Confidence Malicious Infrastructure",
                    "timestamp": 1789314000,
                    "score": 100,
                    "iocs": {
                        "ipv4": ips,
                        "md5": [h for h in hashes if len(h) == 32],
                        "sha256": [h for h in hashes if len(h) == 64],
                        "dns": domains,
                    },
                }
            ],
        }

    @classmethod
    def export_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        name: str = "Sentinel-CTI-Watchlist",
        min_score: float = 75.0,
    ) -> str:
        return json.dumps(cls.export_watchlist(indicators, name=name, min_score=min_score), indent=2)
