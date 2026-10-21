"""Azure Firewall IP Groups ARM template exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class AzureFirewallExporter:
    """Exports high-confidence IP indicators into Azure Firewall IP Groups JSON ARM templates."""

    @classmethod
    def export_ip_group(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        group_name: str = "SentinelCTIThreatFeedIPGroup",
        location: str = "eastus",
        min_score: float = 75.0,
    ) -> Dict[str, Any]:
        """Generate Azure Firewall IP Group resource JSON."""
        ip_addresses: List[str] = []

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

            if ioc_type in ("ipv4", "ipv6") and norm_val not in ip_addresses:
                ip_addresses.append(norm_val)

        return {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [
                {
                    "type": "Microsoft.Network/ipGroups",
                    "apiVersion": "2022-07-01",
                    "name": group_name,
                    "location": location,
                    "properties": {
                        "ipAddresses": ip_addresses,
                    },
                }
            ],
        }

    @classmethod
    def export_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        group_name: str = "SentinelCTIThreatFeedIPGroup",
        min_score: float = 75.0,
    ) -> str:
        return json.dumps(cls.export_ip_group(indicators, group_name=group_name, min_score=min_score), indent=2)
