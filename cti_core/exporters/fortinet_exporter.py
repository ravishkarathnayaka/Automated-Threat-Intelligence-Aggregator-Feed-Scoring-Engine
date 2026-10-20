"""Fortinet FortiGate External Threat Feed (ETF) exporter."""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Union

from cti_core.models.indicator import IndicatorModel, IndicatorRead


class FortinetExporter:
    """Exports indicators into Fortinet FortiGate External Threat Feed format."""

    @classmethod
    def export_ip_feed(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 70.0,
    ) -> str:
        """Export non-whitelisted IPs formatted for FortiGate IP Threat Feed connector."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines: List[str] = [
            "# =====================================================================",
            "# Fortinet FortiGate Threat Feed - SENTINEL CTI Engine",
            f"# Generated: {now_utc}",
            f"# Minimum Score: {min_score}",
            "# =====================================================================",
        ]

        seen_ips = set()

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
            else:  # IndicatorModel
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type).lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)

            if is_whitelisted or score < min_score:
                continue

            if ioc_type not in ("ipv4", "ipv6"):
                continue

            if norm_val in seen_ips:
                continue
            seen_ips.add(norm_val)

            lines.append(norm_val)

        return "\n".join(lines) + "\n"
