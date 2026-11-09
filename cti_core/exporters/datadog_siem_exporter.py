"""Datadog Cloud SIEM Threat Intelligence Lookup and Detection Rule JSON exporter."""

import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class DatadogSIEMExporter:
    """Exports threat indicators into Datadog Cloud SIEM Reference Table and Detection Rule JSON."""

    @classmethod
    def export_reference_table_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        table_name: str = "sentinel_cti_threat_indicators",
        min_score: float = 70.0,
    ) -> str:
        """Generates Datadog Cloud SIEM Reference Table JSON payload."""
        rows: List[Dict[str, Any]] = []

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

            severity = "critical" if score >= 85.0 else "high"
            rows.append(
                {
                    "indicator": norm_val,
                    "type": ioc_type,
                    "confidence_score": score,
                    "severity": severity,
                    "source": "sentinel-cti",
                }
            )

        payload = {
            "table_name": table_name,
            "schema": {
                "primary_keys": ["indicator"],
                "fields": [
                    {"name": "indicator", "type": "STRING"},
                    {"name": "type", "type": "STRING"},
                    {"name": "confidence_score", "type": "NUMBER"},
                    {"name": "severity", "type": "STRING"},
                    {"name": "source", "type": "STRING"},
                ],
            },
            "rows": rows,
        }
        return json.dumps(payload, indent=2)
