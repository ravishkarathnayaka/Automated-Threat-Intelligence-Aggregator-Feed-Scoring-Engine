"""Sigma generic SIEM detection rule exporter."""

from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class SigmaExporter:
    """Generates vendor-agnostic Sigma detection rules from high-fidelity threat indicators."""

    @classmethod
    def generate_network_rule(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        title: str = "Automated CTI Engine High Confidence Malicious Communication",
        min_score: float = 80.0,
    ) -> str:
        """Generates a Sigma YAML rule for network connections to malicious IPs and domains."""
        ips: List[str] = []
        domains: List[str] = []

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

            if ioc_type in ("ipv4", "ipv6") and norm_val not in ips:
                ips.append(norm_val)
            elif ioc_type == "domain" and norm_val not in domains:
                domains.append(norm_val)

        ip_list_str = "\n".join(f"            - '{ip}'" for ip in ips) if ips else "            - '127.0.0.1'"
        domain_list_str = "\n".join(f"            - '{dom}'" for dom in domains) if domains else "            - 'example.invalid'"

        rule_yaml = f"""title: {title}
id: cti-engine-{hash(title) & 0xFFFFFFFFFFFFFFFF:016x}
status: experimental
description: Detects outbound communication to known threat intelligence indicators scored >= {min_score}
author: Automated CTI Engine
references:
    - https://threatintel.local
logsource:
    category: network_connection
detection:
    selection_ip:
        DestinationIp:
{ip_list_str}
    selection_dns:
        query:
{domain_list_str}
    condition: selection_ip or selection_dns
falsepositives:
    - Highly unlikely unless indicator confidence degraded
level: high
tags:
    - attack.initial_access
    - attack.command_and_control
"""
        return rule_yaml.strip()
