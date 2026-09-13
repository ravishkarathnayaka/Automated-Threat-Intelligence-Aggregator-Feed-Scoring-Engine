"""Suricata and Snort IDS/IPS network rule generator for automated threat enforcement."""

from typing import Any, Dict, Iterable, Union

from cti_core.models.indicator import IndicatorModel, IndicatorRead


class RulesExporter:
    """Exports threat indicators to Suricata and Snort rule formats."""

    @staticmethod
    def export_suricata(
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        start_sid: int = 1000001,
        min_score: float = 75.0,
    ) -> str:
        """Render Suricata rules for malicious IPs and domains."""
        rules = [
            "# ===================================================================",
            "# Suricata IDS/IPS Rules - Automated Threat Intelligence Feed",
            f"# Minimum Confidence Threshold: {min_score}",
            "# ===================================================================",
        ]

        current_sid = start_sid
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

            if is_whitelisted or score < min_score:
                continue

            t = ioc_type.lower()
            if t in ("ipv4", "ipv6"):
                rule = (
                    f'alert ip any any -> {norm_val} any ('
                    f'msg:"CTI-ENGINE - Outbound traffic to malicious indicator [{norm_val}] (Score: {score})"; '
                    f'threshold:type limit, track by_src, count 1, seconds 300; '
                    f'classtype:trojan-activity; sid:{current_sid}; rev:1;)'
                )
                rules.append(rule)
                current_sid += 1
            elif t == "domain":
                rule = (
                    f'alert tls $HOME_NET any -> $EXTERNAL_NET any ('
                    f'msg:"CTI-ENGINE - Suspicious TLS SNI connection to [{norm_val}] (Score: {score})"; '
                    f'tls.sni; content:"{norm_val}"; nocase; endswith; '
                    f'classtype:trojan-activity; sid:{current_sid}; rev:1;)'
                )
                rules.append(rule)
                current_sid += 1

        return "\n".join(rules) + "\n"

    @staticmethod
    def export_snort(
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        start_sid: int = 2000001,
        min_score: float = 75.0,
    ) -> str:
        """Render Snort rules for malicious IPs."""
        rules = [
            "# ===================================================================",
            "# Snort IDS/IPS Rules - Automated Threat Intelligence Feed",
            f"# Minimum Confidence Threshold: {min_score}",
            "# ===================================================================",
        ]

        current_sid = start_sid
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

            if is_whitelisted or score < min_score:
                continue

            t = ioc_type.lower()
            if t in ("ipv4", "ipv6"):
                rule = (
                    f'alert ip any any -> {norm_val} any ('
                    f'msg:"CTI-ENGINE - Outbound connection to malicious IP [{norm_val}]"; '
                    f'classtype:trojan-activity; sid:{current_sid}; rev:1;)'
                )
                rules.append(rule)
                current_sid += 1

        return "\n".join(rules) + "\n"
