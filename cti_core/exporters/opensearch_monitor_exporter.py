"""OpenSearch Security Analytics threat detection monitor exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class OpenSearchMonitorExporter:
    """Exports threat indicators into OpenSearch Security Analytics monitor JSON query definitions."""

    @classmethod
    def export_monitor_query(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        index_pattern: str = "security-logs-*",
        min_score: float = 75.0,
    ) -> str:
        """Generates OpenSearch Monitor JSON search query matching threat indicators."""
        ip_terms: List[str] = []
        domain_terms: List[str] = []

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

            if is_whitelisted or score < min_score or not norm_val:
                continue

            if ioc_type in ("ipv4", "ipv6"):
                ip_terms.append(norm_val)
            elif ioc_type == "domain":
                domain_terms.append(norm_val)

        payload = {
            "name": "SENTINEL-CTI Threat Match Detector",
            "type": "monitor",
            "enabled": True,
            "schedule": {"period": {"interval": 5, "unit": "MINUTES"}},
            "inputs": [
                {
                    "search": {
                        "indices": [index_pattern],
                        "query": {
                            "bool": {
                                "should": [
                                    {"terms": {"destination.ip.keyword": ip_terms}},
                                    {"terms": {"source.ip.keyword": ip_terms}},
                                    {"terms": {"dns.question.name.keyword": domain_terms}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                    }
                }
            ],
            "metadata": {
                "engine": "SENTINEL-CTI",
                "total_ips": len(ip_terms),
                "total_domains": len(domain_terms),
            },
        }
        return json.dumps(payload, indent=2)
