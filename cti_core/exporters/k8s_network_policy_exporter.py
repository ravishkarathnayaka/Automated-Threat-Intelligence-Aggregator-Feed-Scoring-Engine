"""Kubernetes NetworkPolicy egress restriction manifest exporter."""

from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class K8sNetworkPolicyExporter:
    """Exports threat indicators into Kubernetes NetworkPolicy egress blocking YAML manifests."""

    @classmethod
    def export_yaml_manifest(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        namespace: str = "default",
        policy_name: str = "sentinel-block-threat-egress",
        min_score: float = 75.0,
    ) -> str:
        """Generates Kubernetes NetworkPolicy YAML with ipBlock exceptions denying outbound malicious egress."""
        except_cidrs: List[str] = []

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
                except_cidrs.append(cidr)

        yaml_lines = [
            "apiVersion: networking.k8s.io/v1",
            "kind: NetworkPolicy",
            "metadata:",
            f"  name: {policy_name}",
            f"  namespace: {namespace}",
            "spec:",
            "  podSelector: {}",
            "  policyTypes:",
            "  - Egress",
            "  egress:",
            "  - to:",
            "    - ipBlock:",
            "        cidr: 0.0.0.0/0",
        ]

        if except_cidrs:
            yaml_lines.append("        except:")
            for c in except_cidrs:
                yaml_lines.append(f"        - {c}")

        return "\n".join(yaml_lines)
