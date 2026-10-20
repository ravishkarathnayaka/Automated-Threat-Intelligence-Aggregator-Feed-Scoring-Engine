"""Check Point Security Gateway external network blocklist exporter."""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Union

from cti_core.models.indicator import IndicatorModel, IndicatorRead


class CheckPointExporter:
    """Exports malicious IP addresses into Check Point Security Gateway Custom Intelligence Feed."""

    @classmethod
    def export_blocklist(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 70.0,
    ) -> str:
        """Format non-whitelisted IP indicators into Check Point external feed format."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines: List[str] = [
            "; =====================================================================",
            "; Check Point Custom Intelligence Feed - SENTINEL CTI Engine",
            f"; Generated: {now_utc}",
            f"; Minimum Score Threshold: {min_score}",
            "; Format: IP/CIDR ; [optional comment]",
            "; =====================================================================",
        ]

        seen_ips = set()

        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                ioc_type = item.get("type", "").lower()
                score = float(item.get("confidence_score", 0.0))
                is_whitelisted = item.get("is_whitelisted", False)
                tags = item.get("tags") or []
            elif isinstance(item, IndicatorRead):
                norm_val = item.normalized_value
                ioc_type = item.type.value.lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
                tags = list(item.tags or [])
            else:  # IndicatorModel
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type).lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
                tags = list(item.tags or [])

            if is_whitelisted or score < min_score:
                continue

            if ioc_type not in ("ipv4", "ipv6"):
                continue

            if norm_val in seen_ips:
                continue
            seen_ips.add(norm_val)

            comment = f"Confidence: {score:.1f} | Tags: {','.join(tags[:2])}" if tags else f"Confidence: {score:.1f}"
            lines.append(f"{norm_val} ; {comment}")

        return "\n".join(lines) + "\n"
