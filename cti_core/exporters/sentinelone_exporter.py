"""SentinelOne Deep Visibility (S1QL) query generator."""

from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class SentinelOneExporter:
    """Exports scored threat indicators into SentinelOne Deep Visibility S1QL search queries."""

    @classmethod
    def export_query(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 75.0,
    ) -> str:
        """Generate S1QL query string searching for network and endpoint IoCs."""
        ips: List[str] = []
        domains: List[str] = []
        hashes: List[str] = []

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
            elif ioc_type in ("sha256", "sha1", "md5") and norm_val not in hashes:
                hashes.append(norm_val)

        clauses: List[str] = []
        if ips:
            formatted_ips = ", ".join(f'"{ip}"' for ip in ips)
            clauses.append(f"DstIP in ({formatted_ips})")
        if domains:
            formatted_domains = ", ".join(f'"{d}"' for d in domains)
            clauses.append(f"DNSRequest in ({formatted_domains})")
        if hashes:
            formatted_hashes = ", ".join(f'"{h}"' for h in hashes)
            clauses.append(f"TgtFileSHA256 in ({formatted_hashes})")

        if not clauses:
            return "// No active indicators meeting score threshold\nEventType = \"Process Creation\" and false"

        return " or\n".join(clauses)
