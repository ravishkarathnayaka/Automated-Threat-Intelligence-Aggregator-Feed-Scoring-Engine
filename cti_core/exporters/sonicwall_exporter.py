"""SonicWall SonicOS CLI address-object and address-group exporter."""

from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class SonicWallExporter:
    """Exports threat indicators into SonicWall SonicOS CLI commands."""

    @classmethod
    def export_cli_commands(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        group_name: str = "SENTINEL_DROP_GROUP",
        min_score: float = 75.0,
    ) -> str:
        """Generates SonicOS CLI commands to configure address objects and add them to a group."""
        commands: List[str] = [
            "! SonicWall SonicOS Threat Intelligence Integration - SENTINEL CTI",
            "configure",
        ]

        obj_names: List[str] = []
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
                name = f"THREAT_IP_{norm_val.replace('.', '_')}"
                commands.append(f"address-object ipv4 {name} host {norm_val} zone WAN")
                obj_names.append(name)
            elif ioc_type == "domain":
                name = f"THREAT_FQDN_{norm_val.replace('.', '_')}"
                commands.append(f"address-object fqdn {name} domain {norm_val} zone WAN")
                obj_names.append(name)

        if obj_names:
            commands.append(f"address-group ipv4 {group_name}")
            for obj in obj_names:
                commands.append(f"  address-object ipv4 {obj}")
            commands.append("exit")

        commands.append("commit")
        return "\n".join(commands)
