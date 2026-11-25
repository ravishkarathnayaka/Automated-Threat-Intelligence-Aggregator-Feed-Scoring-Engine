"""Azure Front Door (AFD) Custom WAF Rule JSON manifest exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class AzureFrontDoorWAFExporter:
    """Exports threat IPs into Azure Front Door WAF custom rule JSON configurations."""

    @classmethod
    def export_waf_rules_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        policy_name: str = "SentinelFrontDoorWAFPolicy",
        rule_name: str = "BlockThreatActors",
        priority: int = 100,
        min_score: float = 75.0,
    ) -> str:
        """Generates Azure Front Door WAF custom rule payload."""
        ip_cidrs: List[str] = []

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
                ip_cidrs.append(cidr)

        if not ip_cidrs:
            ip_cidrs.append("255.255.255.255/32")

        payload = {
            "policyName": policy_name,
            "customRules": [
                {
                    "name": rule_name,
                    "priority": priority,
                    "ruleType": "MatchRule",
                    "action": "Block",
                    "matchConditions": [
                        {
                            "matchVariable": "RemoteAddr",
                            "operator": "IPMatch",
                            "negateCondition": False,
                            "matchValue": ip_cidrs,
                        }
                    ],
                }
            ],
        }
        return json.dumps(payload, indent=2)
