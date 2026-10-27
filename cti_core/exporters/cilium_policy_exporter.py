"""Cilium eBPF NetworkPolicy (CNP) L3/L4/L7 egress denial exporter."""

from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class CiliumPolicyExporter:
    """Exports threat indicators into CiliumNetworkPolicy (CNP) YAML manifests."""

    @classmethod
    def export_yaml_manifest(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        namespace: str = "production",
        policy_name: str = "cilium-deny-threat-actors",
        min_score: float = 75.0,
    ) -> str:
        """Generates CiliumNetworkPolicy egress denial manifest."""
        cidr_rules: List[str] = []
        fqdn_rules: List[str] = []

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
                cidr_rules.append(cidr)
            elif ioc_type == "domain":
                fqdn_rules.append(norm_val)

        yaml_lines = [
            "apiVersion: cilium.io/v2",
            "kind: CiliumNetworkPolicy",
            "metadata:",
            f"  name: {policy_name}",
            f"  namespace: {namespace}",
            "spec:",
            "  endpointSelector:",
            "    matchLabels: {}",
            "  egressDeny:",
        ]

        if cidr_rules:
            yaml_lines.append("  - toCIDRSet:")
            for c in cidr_rules:
                yaml_lines.append(f"    - cidr: \"{c}\"")

        if fqdn_rules:
            yaml_lines.append("  - toFQDNs:")
            for f in fqdn_rules:
                yaml_lines.append(f"    - matchName: \"{f}\"")

        return "\n".join(yaml_lines)
