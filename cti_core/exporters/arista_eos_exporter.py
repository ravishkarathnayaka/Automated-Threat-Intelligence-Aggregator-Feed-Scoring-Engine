"""Arista EOS access-list (ACL) configuration exporter."""

from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class AristaEOSExporter:
    """Exports threat indicators into Arista EOS IP access-list drop rules."""

    @classmethod
    def export_acl_config(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        acl_name: str = "SENTINEL_DROP_ACL",
        min_score: float = 75.0,
    ) -> str:
        """Generates Arista EOS IP access-list commands."""
        commands: List[str] = [
            f"! Arista EOS Threat Mitigation Access-List - SENTINEL CTI",
            f"ip access-list {acl_name}",
        ]

        seq = 10
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
                commands.append(f" {seq} deny ip any {cidr} log")
                seq += 10

        commands.append(f" {seq} permit ip any any")
        commands.append("exit")
        return "\n".join(commands)
