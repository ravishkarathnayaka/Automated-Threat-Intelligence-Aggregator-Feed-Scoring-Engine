"""Google Cloud Armor WAF security policy edge expression exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class GoogleCloudArmorExporter:
    """Exports threat IPs into Google Cloud Armor edge security policy rule configurations."""

    @classmethod
    def export_policy_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        policy_name: str = "sentinel-cloud-armor-blocklist",
        priority: int = 1000,
        min_score: float = 75.0,
    ) -> str:
        """Generates Google Cloud Armor SecurityPolicy rule JSON."""
        src_ip_ranges: List[str] = []

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

            if ioc_type == "ipv4":
                cidr = f"{norm_val}/32" if "/" not in norm_val else norm_val
                src_ip_ranges.append(cidr)
            elif ioc_type == "ipv6":
                cidr = f"{norm_val}/128" if "/" not in norm_val else norm_val
                src_ip_ranges.append(cidr)

        # Cloud Armor limits versionedExpr SRC_IPS_V1 to 10 ranges per rule
        rules = []
        chunks = [src_ip_ranges[i : i + 10] for i in range(0, len(src_ip_ranges), 10)] or [["255.255.255.255/32"]]

        for idx, chunk in enumerate(chunks):
            rules.append(
                {
                    "action": "deny(403)",
                    "priority": priority + idx,
                    "description": f"SENTINEL-CTI Automated Threat Block Rule #{idx + 1}",
                    "match": {
                        "versionedExpr": "SRC_IPS_V1",
                        "config": {"srcIpRanges": chunk},
                    },
                    "preview": False,
                }
            )

        payload = {
            "name": policy_name,
            "type": "CLOUD_ARMOR",
            "rules": rules,
        }
        return json.dumps(payload, indent=2)
