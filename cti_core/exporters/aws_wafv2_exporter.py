"""AWS WAFv2 IPSet and WebACL rule group JSON exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class AWSWAFv2Exporter:
    """Exports threat IPs into AWS WAFv2 IPSet JSON payloads for CloudFront and ALB protection."""

    @classmethod
    def export_ipset_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        ipset_name: str = "Sentinel-CTI-WAFv2-IPSet",
        scope: str = "REGIONAL",
        min_score: float = 75.0,
    ) -> str:
        """Generates AWS WAFv2 CreateIPSet / UpdateIPSet compatible JSON."""
        ipv4_addresses: List[str] = []
        ipv6_addresses: List[str] = []

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
                ipv4_addresses.append(cidr)
            elif ioc_type == "ipv6":
                cidr = f"{norm_val}/128" if "/" not in norm_val else norm_val
                ipv6_addresses.append(cidr)

        payload = {
            "Name": ipset_name,
            "Scope": scope,
            "Description": "Automated SENTINEL-CTI high-confidence malicious IP blocklist",
            "IPAddressVersion": "IPV4",
            "Addresses": ipv4_addresses,
            "IPv6Addresses": ipv6_addresses,
        }
        return json.dumps(payload, indent=2)
