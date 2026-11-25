"""Traefik IngressRoute & Middleware IP allow/deny list YAML manifest exporter."""

from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class TraefikMiddlewareExporter:
    """Exports threat IP indicators into Traefik IngressRoute Middleware YAML manifests."""

    @classmethod
    def export_yaml_manifest(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        namespace: str = "traefik-system",
        middleware_name: str = "sentinel-threat-drop-middleware",
        min_score: float = 75.0,
    ) -> str:
        """Generates Traefik v1alpha1 Middleware with IPWhiteList/IPAllowList restriction."""
        ip_cidrs: List[str] = []

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
                ip_cidrs.append(cidr)
            elif ioc_type == "ipv6":
                cidr = f"{norm_val}/128" if "/" not in norm_val else norm_val
                ip_cidrs.append(cidr)

        if not ip_cidrs:
            ip_cidrs.append("255.255.255.255/32")

        yaml_lines = [
            "apiVersion: traefik.io/v1alpha1",
            "kind: Middleware",
            "metadata:",
            f"  name: {middleware_name}",
            f"  namespace: {namespace}",
            "spec:",
            "  plugin:",
            "    blockthreats:",
            "      blockedRanges:",
        ]
        for cidr in ip_cidrs:
            yaml_lines.append(f'      - "{cidr}"')

        return "\n".join(yaml_lines)
