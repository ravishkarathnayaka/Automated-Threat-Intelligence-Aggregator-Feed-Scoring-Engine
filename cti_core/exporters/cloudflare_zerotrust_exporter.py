"""Cloudflare Zero Trust Gateway list and firewall policy exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class CloudflareZeroTrustExporter:
    """Exports threat indicators into Cloudflare Zero Trust Gateway list items."""

    @classmethod
    def export_list_items(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        list_name: str = "Sentinel-Threat-Feed",
        min_score: float = 75.0,
    ) -> str:
        """Generates Cloudflare Zero Trust Gateway List JSON payload."""
        items: List[Dict[str, str]] = []

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

            if ioc_type in ("ipv4", "domain", "url"):
                items.append({
                    "value": norm_val,
                    "description": f"SENTINEL-CTI auto block (Score: {score})",
                })

        payload = {
            "name": list_name,
            "type": "SERIAL",
            "description": "Automated Threat Intelligence Blocklist managed by SENTINEL-CTI",
            "items": items,
        }
        return json.dumps(payload, indent=2)
