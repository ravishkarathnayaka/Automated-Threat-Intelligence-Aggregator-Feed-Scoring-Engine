"""ModSecurity Web Application Firewall SecRule exporter."""

from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class ModSecurityWAFExporter:
    """Exports threat indicators into OWASP ModSecurity Core Rule Set (CRS) SecRule directives."""

    @classmethod
    def export_secrules(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        start_id: int = 2200000,
        min_score: float = 75.0,
    ) -> str:
        """Generates ModSecurity SecRule directives for IP and domain request blocking."""
        rules: List[str] = [
            f"# ModSecurity WAF Threat Intelligence Enforcement Rules - SENTINEL CTI",
            f"# Base Rule ID Range: {start_id}+",
        ]

        curr_id = start_id
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
                rules.append(
                    f'SecRule REMOTE_ADDR "@ipMatch {norm_val}" '
                    f'"id:{curr_id},phase:1,deny,status:403,log,msg:\'SENTINEL-CTI: Malicious client IP detected\',tag:\'cti_threat\',severity:CRITICAL"'
                )
                curr_id += 1
            elif ioc_type == "domain":
                rules.append(
                    f'SecRule REQUEST_HEADERS:Host "@streq {norm_val}" '
                    f'"id:{curr_id},phase:1,deny,status:403,log,msg:\'SENTINEL-CTI: Host header matches malicious C2 domain\',tag:\'cti_threat\',severity:CRITICAL"'
                )
                curr_id += 1

        return "\n".join(rules)
