"""Palo Alto Networks PAN-OS External Dynamic List (EDL) multi-format exporter."""

from typing import Any, Dict, Iterable, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class PaloAltoEDLExporter:
    """Exports indicators for Palo Alto PAN-OS External Dynamic Lists (EDL)."""

    @classmethod
    def export_ip_edl(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 75.0,
    ) -> str:
        """Outputs IP list suitable for PAN-OS IP EDL object."""
        lines = ["# Palo Alto PAN-OS External Dynamic List - IP Blocklist"]
        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                ioc_type = item.get("type", "").lower()
                score = float(item.get("confidence_score", 0.0))
                is_whitelisted = item.get("is_whitelisted", False)
            else:
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type).lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)

            if is_whitelisted or score < min_score or not norm_val:
                continue

            if ioc_type in ("ipv4", "ipv6") and norm_val not in lines:
                lines.append(norm_val)

        return "\n".join(lines)

    @classmethod
    def export_domain_edl(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 75.0,
    ) -> str:
        """Outputs Domain list suitable for PAN-OS Domain EDL object."""
        lines = ["# Palo Alto PAN-OS External Dynamic List - Domain Blocklist"]
        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                ioc_type = item.get("type", "").lower()
                score = float(item.get("confidence_score", 0.0))
                is_whitelisted = item.get("is_whitelisted", False)
            else:
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type).lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)

            if is_whitelisted or score < min_score or not norm_val:
                continue

            if ioc_type == "domain" and norm_val not in lines:
                lines.append(norm_val)

        return "\n".join(lines)
