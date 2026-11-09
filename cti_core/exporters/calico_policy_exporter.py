"""Project Calico GlobalNetworkPolicy Kubernetes CNI egress and ingress denial exporter."""

from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class CalicoPolicyExporter:
    """Exports threat IPs into Project Calico GlobalNetworkPolicy YAML manifests."""

    @classmethod
    def export_yaml_manifest(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        policy_name: str = "sentinel-calico-deny-threat-feeds",
        order: int = 50,
        min_score: float = 75.0,
    ) -> str:
        """Generates Project Calico v3 GlobalNetworkPolicy YAML with Deny rules."""
        nets: List[str] = []

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

            if ioc_type == "ipv4":
                cidr = f"{norm_val}/32" if "/" not in norm_val else norm_val
                nets.append(cidr)
            elif ioc_type == "ipv6":
                cidr = f"{norm_val}/128" if "/" not in norm_val else norm_val
                nets.append(cidr)

        if not nets:
            nets.append("255.255.255.255/32")

        yaml_lines = [
            "apiVersion: projectcalico.org/v3",
            "kind: GlobalNetworkPolicy",
            "metadata:",
            f"  name: {policy_name}",
            "spec:",
            f"  order: {order}",
            "  selector: all()",
            "  types:",
            "  - Ingress",
            "  - Egress",
            "  ingress:",
            "  - action: Deny",
            "    source:",
            "      nets:",
        ]
        for net in nets:
            yaml_lines.append(f'      - "{net}"')

        yaml_lines.extend(
            [
                "  egress:",
                "  - action: Deny",
                "    destination:",
                "      nets:",
            ]
        )
        for net in nets:
            yaml_lines.append(f'      - "{net}"')

        return "\n".join(yaml_lines)
