"""F5 BIG-IP AFM / LTM IP intelligence data group exporter."""

from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class F5BigIPExporter:
    """Exports threat indicators into F5 tmsh data-group commands for IP Intelligence enforcement."""

    @classmethod
    def export_tmsh_commands(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        data_group_name: str = "sentinel_malicious_ips",
        min_score: float = 75.0,
    ) -> str:
        """Generates F5 BIG-IP TMSH commands for address data-group creation."""
        commands: List[str] = [
            f"# F5 BIG-IP TMSH Threat Data Group - SENTINEL CTI",
            f"modify ltm data-group internal {data_group_name} type ip records replace-all-with {{",
        ]

        entries: List[str] = []
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
                entries.append(f'    {cidr} {{ data "score={score}" }}')

        commands.extend(entries)
        commands.append("}")
        return "\n".join(commands)
