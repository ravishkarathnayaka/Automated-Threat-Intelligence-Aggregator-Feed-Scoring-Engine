"""Istio Service Mesh AuthorizationPolicy egress and ingress denial exporter."""

from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class IstioPolicyExporter:
    """Exports threat indicators into Istio AuthorizationPolicy DENY YAML manifests."""

    @classmethod
    def export_yaml_manifest(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        namespace: str = "istio-system",
        policy_name: str = "sentinel-block-threat-actors",
        min_score: float = 75.0,
    ) -> str:
        """Generates Istio AuthorizationPolicy with ipBlocks denying malicious traffic."""
        ip_blocks: List[str] = []

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
                cidr = f"{norm_val}/32" if ioc_type == "ipv4" and "/" not in norm_val else norm_val
                ip_blocks.append(cidr)

        yaml_lines = [
            "apiVersion: security.istio.io/v1beta1",
            "kind: AuthorizationPolicy",
            "metadata:",
            f"  name: {policy_name}",
            f"  namespace: {namespace}",
            "spec:",
            "  action: DENY",
            "  rules:",
            "  - from:",
            "    - source:",
            "        ipBlocks:",
        ]

        if ip_blocks:
            for ip in ip_blocks:
                yaml_lines.append(f"        - \"{ip}\"")
        else:
            yaml_lines.append("        - \"255.255.255.255/32\"")

        return "\n".join(yaml_lines)
