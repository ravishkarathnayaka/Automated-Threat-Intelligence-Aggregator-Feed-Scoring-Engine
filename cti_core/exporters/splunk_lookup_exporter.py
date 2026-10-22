"""Splunk Enterprise Security Threat Intelligence Framework lookup table exporter."""

import csv
import io
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class SplunkLookupExporter:
    """Exports scored threat indicators into Splunk ES KV-store / CSV lookup table format."""

    HEADERS = ["threat_key", "indicator", "type", "confidence", "threat_category", "weight", "description"]

    @classmethod
    def export_csv(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 65.0,
    ) -> str:
        """Generate Splunk ES compliant threat lookup CSV."""
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(cls.HEADERS)

        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                ioc_type = item.get("type", "").lower()
                score = float(item.get("confidence_score", 0.0))
                is_whitelisted = item.get("is_whitelisted", False)
                tags = item.get("tags") or []
            elif isinstance(item, IndicatorRead):
                norm_val = item.normalized_value
                ioc_type = item.type.value.lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
                tags = list(item.tags or [])
            else:
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type).lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
                tags = list(item.tags or [])

            if is_whitelisted or score < min_score or not norm_val:
                continue

            threat_key = f"sentinel_{ioc_type}_{abs(hash(norm_val)) % 10000000}"
            weight = round(score / 10.0, 1)
            cat = tags[0] if tags else "malicious-activity"
            desc = f"SENTINEL-CTI confidence: {score:.1f}"

            writer.writerow([threat_key, norm_val, ioc_type, f"{score:.1f}", cat, f"{weight:.1f}", desc])

        return output.getvalue()
