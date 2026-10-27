"""Envoy Proxy RBAC and Lua network filter configuration exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class EnvoyProxyExporter:
    """Exports threat indicators into Envoy Proxy RBAC network filter JSON configuration."""

    @classmethod
    def export_rbac_filter(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        filter_name: str = "sentinel_ip_block_filter",
        min_score: float = 75.0,
    ) -> str:
        """Generates Envoy RBAC filter configuration with DENY action."""
        principals: List[Dict[str, Any]] = []

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
                prefix = 32 if ioc_type == "ipv4" else 128
                ip_clean = norm_val.split("/")[0]
                principals.append({
                    "direct_remote_ip": {
                        "address_prefix": ip_clean,
                        "prefix_len": prefix,
                    }
                })

        payload = {
            "name": "envoy.filters.network.rbac",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.network.rbac.v3.RBAC",
                "stat_prefix": filter_name,
                "rules": {
                    "action": "DENY",
                    "policies": {
                        "sentinel_threat_policy": {
                            "permissions": [{"any": True}],
                            "principals": principals,
                        }
                    },
                },
            },
        }
        return json.dumps(payload, indent=2)
