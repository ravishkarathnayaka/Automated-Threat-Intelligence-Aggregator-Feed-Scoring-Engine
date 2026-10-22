"""CrowdStrike Falcon Data Replicator (FDR) hunting query exporter."""

from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class CrowdStrikeFDRExporter:
    """Generates Presto/Athena SQL queries for CrowdStrike Falcon Data Replicator (FDR)."""

    @classmethod
    def generate_athena_sql(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 75.0,
    ) -> str:
        """Generates Athena/Presto SQL query targeting NetworkConnectIP4 and DnsRequest events."""
        ips: List[str] = []
        domains: List[str] = []

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

            if ioc_type in ("ipv4", "ipv6") and norm_val not in ips:
                ips.append(norm_val)
            elif ioc_type == "domain" and norm_val not in domains:
                domains.append(norm_val)

        ip_filter = ", ".join(f"'{ip}'" for ip in ips) if ips else "'127.0.0.1'"
        domain_filter = ", ".join(f"'{dom}'" for dom in domains) if domains else "'example.invalid'"

        return f"""-- CrowdStrike Falcon Data Replicator (FDR) Athena Threat Hunt
SELECT
    aid,
    ComputerName,
    event_platform,
    timestamp,
    RemoteAddressIP4,
    DomainName
FROM
    fdr_events_table
WHERE
    (event_simpleName = 'NetworkConnectIP4' AND RemoteAddressIP4 IN ({ip_filter}))
    OR
    (event_simpleName = 'DnsRequest' AND DomainName IN ({domain_filter}))
ORDER BY
    timestamp DESC
LIMIT 500;"""
