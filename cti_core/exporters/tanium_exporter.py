"""Tanium Threat Response IOC package exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class TaniumExporter:
    """Exports indicators in Tanium Threat Response intel definition JSON format."""

    TYPE_MAP = {
        "ipv4": "IPAddress",
        "ipv6": "IPAddress",
        "domain": "DomainName",
        "sha256": "Sha256",
        "md5": "Md5",
        "url": "URL",
    }

    @classmethod
    def export_package(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        package_name: str = "Sentinel-Threat-Response-Package",
        min_score: float = 70.0,
    ) -> Dict[str, Any]:
        """Generate Tanium Threat Response intel document."""
        tanium_iocs: List[Dict[str, Any]] = []

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

            mapped_type = cls.TYPE_MAP.get(ioc_type)
            if not mapped_type:
                continue

            severity = "Critical" if score >= 85.0 else ("High" if score >= 70.0 else "Medium")
            tanium_iocs.append({
                "type": mapped_type,
                "value": norm_val,
                "severity": severity,
                "score": score,
                "author": "SENTINEL-CTI",
            })

        return {
            "name": package_name,
            "schema_version": "2.0",
            "threat_intel_iocs": tanium_iocs,
        }

    @classmethod
    def export_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        package_name: str = "Sentinel-Threat-Response-Package",
        min_score: float = 70.0,
    ) -> str:
        return json.dumps(cls.export_package(indicators, package_name=package_name, min_score=min_score), indent=2)
