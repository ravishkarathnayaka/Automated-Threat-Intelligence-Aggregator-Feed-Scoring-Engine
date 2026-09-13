"""DNS Response Policy Zone (RPZ) exporter for BIND 9, Pi-hole, and Unbound."""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Union

from cti_core.models.indicator import IndicatorModel, IndicatorRead


class DNSRPZExporter:
    """Generates standard RFC DNS Response Policy Zone (RPZ) zone files."""

    @staticmethod
    def export_rpz(
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        zone_name: str = "rpz.threat-intel.local",
        min_score: float = 70.0,
    ) -> str:
        """Render standard BIND RPZ zone file with CNAME . (NXDOMAIN) action."""
        now = datetime.now(timezone.utc)
        serial = now.strftime("%Y%m%d%H")

        domains: List[str] = []
        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                ioc_type = item.get("type", "")
                score = float(item.get("confidence_score", 0.0))
                is_whitelisted = item.get("is_whitelisted", False)
            elif isinstance(item, IndicatorRead):
                norm_val = item.normalized_value
                ioc_type = item.type.value
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
            else:
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type)
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)

            if ioc_type.lower() == "domain" and not is_whitelisted and score >= min_score:
                clean_domain = norm_val.lower().rstrip(".")
                domains.append(clean_domain)

        unique_domains = sorted(list(dict.fromkeys(domains)))

        lines = [
            "; ===================================================================",
            "; DNS Response Policy Zone (RPZ) for BIND / Pi-hole / Unbound",
            f"; Zone: {zone_name}",
            f"; Serial: {serial} | Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"; Minimum Confidence Threshold: {min_score} | Blocked Domains: {len(unique_domains)}",
            "; ===================================================================",
            "$TTL 300",
            "@ IN SOA localhost. root.localhost. (",
            f"    {serial} ; serial",
            "    3600       ; refresh (1 hour)",
            "    1800       ; retry (30 mins)",
            "    604800     ; expire (1 week)",
            "    300        ; minimum (5 mins)",
            ")",
            "@ IN NS localhost.",
            "",
            "; --- Policy Trigger & Actions (CNAME . forces NXDOMAIN) ---",
        ]

        for d in unique_domains:
            lines.append(f"{d} CNAME .")
            lines.append(f"*.{d} CNAME .")

        return "\n".join(lines) + "\n"
