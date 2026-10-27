"""Okta Identity Network Zone IP blocklist REST API payload exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class OktaZoneExporter:
    """Exports threat indicators into Okta Network Zone IP blocklist REST API payload."""

    @classmethod
    def export_zone_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        zone_name: str = "Sentinel-Threat-Actors-Blocklist",
        min_score: float = 75.0,
    ) -> str:
        """Generates Okta Network Zone JSON payload for POST /api/v1/zones."""
        gateways: List[Dict[str, str]] = []

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
                cidr = f"{norm_val}/32" if ioc_type == "ipv4" and "/" not in norm_val else norm_val
                gateways.append({
                    "type": "CIDR",
                    "value": cidr,
                })

        payload = {
            "type": "IP",
            "name": zone_name,
            "status": "ACTIVE",
            "usage": "BLOCKLIST",
            "gateways": gateways,
        }
        return json.dumps(payload, indent=2)
