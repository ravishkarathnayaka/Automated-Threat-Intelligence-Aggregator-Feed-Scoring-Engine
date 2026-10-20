"""Cloudflare WAF IP Access Rules exporter for automated edge firewall sync."""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Union

from cti_core.models.indicator import IndicatorModel, IndicatorRead


class CloudflareWAFExporter:
    """Exports malicious IP indicators formatted for Cloudflare IP Access Rules API."""

    @classmethod
    def export_access_rules(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 70.0,
        mode: str = "block",
    ) -> List[Dict[str, Any]]:
        """Export indicators into Cloudflare IP Access Rule JSON objects."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        rules: List[Dict[str, Any]] = []
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

            target = "ip_range" if "/" in norm_val else ("ip6" if ":" in norm_val else "ip")

            rules.append({
                "mode": mode,
                "configuration": {
                    "target": target,
                    "value": norm_val,
                },
                "notes": f"SENTINEL-CTI | Score: {score:.1f} | Sync: {now_utc}",
            })

        return rules
