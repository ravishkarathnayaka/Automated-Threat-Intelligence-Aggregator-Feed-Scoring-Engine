"""Kong API Gateway IP Restriction plugin JSON configuration exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class KongGatewayExporter:
    """Exports threat IPs into Kong API Gateway ip-restriction plugin JSON configuration."""

    @classmethod
    def export_plugin_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        status_code: int = 403,
        message: str = "Access denied by SENTINEL-CTI Threat Intelligence Policy",
        min_score: float = 75.0,
    ) -> str:
        """Generates Kong Admin API ip-restriction plugin JSON payload."""
        deny_list: List[str] = []

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
                deny_list.append(norm_val)

        payload = {
            "name": "ip-restriction",
            "enabled": True,
            "config": {
                "deny": deny_list if deny_list else ["255.255.255.255"],
                "status": status_code,
                "message": message,
            },
        }
        return json.dumps(payload, indent=2)
