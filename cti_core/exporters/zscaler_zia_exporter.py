"""Zscaler Internet Access (ZIA) Secure Web Gateway custom URL category & IP destination exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class ZscalerZIAExporter:
    """Exports threat domains, URLs, and IPs into Zscaler ZIA Custom URL Category JSON format."""

    @classmethod
    def export_zia_category_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        category_id: str = "CUSTOM_01",
        configured_name: str = "SENTINEL_CTI_MALICIOUS_BLOCK",
        min_score: float = 75.0,
    ) -> str:
        """Generates Zscaler ZIA API custom URL category payload."""
        urls: List[str] = []
        ip_ranges: List[str] = []

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

            if ioc_type in ("domain", "url"):
                clean_url = norm_val.replace("https://", "").replace("http://", "")
                urls.append(clean_url)
            elif ioc_type in ("ipv4", "ipv6"):
                ip_ranges.append(norm_val)

        payload = {
            "id": category_id,
            "configuredName": configured_name,
            "superCategory": "USER_DEFINED",
            "customCategory": True,
            "urls": urls,
            "dbCategorizedUrls": [],
            "ipRanges": ip_ranges,
            "ipRangesRetainingParentCategory": [],
        }
        return json.dumps(payload, indent=2)
