"""Microsoft Sentinel Kusto Query Language (KQL) threat hunting exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class MicrosoftSentinelExporter:
    """Generates optimized KQL queries for Microsoft Sentinel analytics and threat hunting."""

    @classmethod
    def export_kql(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 75.0,
    ) -> str:
        """Export indicators into KQL hunting rules targeting Azure network and DNS logs."""
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

            if is_whitelisted or score < min_score:
                continue

            if ioc_type in ("ipv4", "ipv6") and norm_val not in ips:
                ips.append(norm_val)
            elif ioc_type == "domain" and norm_val not in domains:
                domains.append(norm_val)

        lines = [
            "// Sentinel CTI Automated Microsoft Sentinel Hunting Rule",
            "// Target Tables: CommonSecurityLog, DnsEvents, DeviceNetworkEvents",
        ]

        if ips:
            lines.append(f"let BlocklistIPs = dynamic({json.dumps(ips[:100])});")
            lines.append(
                "CommonSecurityLog\n"
                "| where DestinationIP in (BlocklistIPs)\n"
                "| project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, Activity"
            )

        if domains:
            if ips:
                lines.append("\n// DNS Hunting Section")
            lines.append(f"let MaliciousDomains = dynamic({json.dumps(domains[:100])});")
            lines.append(
                "DnsEvents\n"
                "| where Name in (MaliciousDomains)\n"
                "| project TimeGenerated, ClientIP, Name, QueryType"
            )

        if not ips and not domains:
            return "// No indicators meeting confidence threshold\nprint Status=\"No active threats\""

        return "\n".join(lines)
