"""Plaintext firewall blocklist exporter formatted for iptables, pfSense, and Palo Alto/Fortinet EDLs."""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Union

from cti_core.models.indicator import IndicatorModel, IndicatorRead


class FirewallBlocklistExporter:
    """Exports malicious IP addresses into a high-performance plaintext blocklist format."""

    @staticmethod
    def export_plaintext(
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 70.0,
        include_header: bool = True,
    ) -> str:
        """Filter and format IP indicators into a newline-separated IP blocklist."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        valid_ips: List[str] = []

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
            else:  # IndicatorModel
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type)
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)

            # Only IP addresses, non-whitelisted, meeting minimum confidence threshold
            if ioc_type.lower() in ("ipv4", "ipv6") and not is_whitelisted and score >= min_score:
                valid_ips.append(norm_val)

        # Deduplicate while preserving order
        unique_ips = list(dict.fromkeys(valid_ips))

        lines = []
        if include_header:
            lines.append("# =====================================================================")
            lines.append("# Automated Threat Intelligence Firewall Blocklist")
            lines.append(f"# Generated: {now_utc}")
            lines.append(f"# Minimum Confidence Score Threshold: {min_score}")
            lines.append(f"# Total Blocked IPs: {len(unique_ips)}")
            lines.append("# Compatible with: iptables, pfSense, Palo Alto EDL, Fortinet Threat Feeds")
            lines.append("# =====================================================================")

        lines.extend(unique_ips)
        return "\n".join(lines) + "\n"
