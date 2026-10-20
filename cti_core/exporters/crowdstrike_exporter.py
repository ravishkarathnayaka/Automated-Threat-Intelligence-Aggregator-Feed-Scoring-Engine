"""CrowdStrike Falcon Custom IOC CSV format exporter."""

import csv
import io
from typing import Any, Dict, Iterable, Union

from cti_core.models.indicator import IndicatorModel, IndicatorRead


class CrowdStrikeExporter:
    """Exports scored threat indicators into CrowdStrike Falcon Custom IOC import CSV format."""

    TYPE_MAP = {
        "ipv4": "ipv4",
        "ipv6": "ipv6",
        "domain": "domain",
        "md5": "md5",
        "sha256": "sha256",
    }

    HEADERS = ["type", "value", "action", "severity", "description"]

    @classmethod
    def _map_severity(cls, score: float) -> str:
        if score >= 85.0:
            return "critical"
        if score >= 70.0:
            return "high"
        if score >= 40.0:
            return "medium"
        return "low"

    @classmethod
    def export(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        default_action: str = "prevent",
        min_score: float = 70.0,
    ) -> str:
        """Generate CrowdStrike Falcon Custom IOC compliant CSV."""
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(cls.HEADERS)

        seen = set()

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

            if is_whitelisted or score < min_score:
                continue

            cs_type = cls.TYPE_MAP.get(ioc_type)
            if not cs_type or norm_val in seen:
                continue
            seen.add(norm_val)

            sev = cls._map_severity(score)
            action = default_action if score >= 85.0 else "detect"
            desc = f"SENTINEL-CTI Auto-Enforcement (Confidence: {score:.1f})"

            writer.writerow([cs_type, norm_val, action, sev, desc])

        return output.getvalue()
