"""AWS Network Firewall stateful IP rule group JSON exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class AWSNetworkFirewallExporter:
    """Exports scored IP indicators into AWS Network Firewall stateful drop rule groups."""

    @classmethod
    def export_rule_group(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        rule_group_name: str = "Sentinel-CTI-Blocklist",
        capacity: int = 1000,
        min_score: float = 75.0,
    ) -> Dict[str, Any]:
        """Generate AWS Network Firewall RuleGroup JSON definition."""
        rules: List[Dict[str, Any]] = []

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

            if ioc_type in ("ipv4", "ipv6"):
                dest = norm_val if "/" in norm_val else f"{norm_val}/32"
                rules.append({
                    "Action": "DROP",
                    "Header": {
                        "Direction": "FORWARD",
                        "Protocol": "IP",
                        "Source": "ANY",
                        "SourcePort": "ANY",
                        "Destination": dest,
                        "DestinationPort": "ANY",
                    },
                    "RuleOptions": [
                        {"Keyword": f'msg:"Sentinel CTI Block IP [{norm_val}]"'},
                        {"Keyword": "sid:" + str(3000000 + len(rules))},
                    ],
                })

        return {
            "RuleGroup": {
                "RuleGroupName": rule_group_name,
                "Type": "STATEFUL",
                "Capacity": capacity,
                "RulesSource": {
                    "StatefulRules": rules,
                },
            }
        }

    @classmethod
    def export_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 75.0,
    ) -> str:
        return json.dumps(cls.export_rule_group(indicators, min_score=min_score), indent=2)
