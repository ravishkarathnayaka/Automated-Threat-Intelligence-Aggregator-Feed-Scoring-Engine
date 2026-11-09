"""Netskope Cloud Access Security Broker (CASB) & Secure Web Gateway (SWG) URL/IP list exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class NetskopeCASBExporter:
    """Exports high-confidence threat domains, URLs, and IPs into Netskope REST API v2 URL List JSON."""

    @classmethod
    def export_url_list_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        list_name: str = "Sentinel-CTI-Block-List",
        list_type: str = "exact",
        min_score: float = 75.0,
    ) -> str:
        """Generates Netskope REST API v2 URL/IP custom list payload."""
        urls_and_ips: List[str] = []

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

            if ioc_type in ("domain", "url", "ipv4", "ipv6"):
                urls_and_ips.append(norm_val)

        payload = {
            "name": list_name,
            "data": {
                "urls": urls_and_ips if urls_and_ips else ["malicious-placeholder.invalid"],
                "type": list_type,
            },
        }
        return json.dumps(payload, indent=2)
