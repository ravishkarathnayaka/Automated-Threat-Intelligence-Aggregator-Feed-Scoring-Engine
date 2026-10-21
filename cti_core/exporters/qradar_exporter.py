"""IBM QRadar Reference Set and Reference Map exporter."""

import io
import csv
import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class QRadarExporter:
    """Exports indicators for IBM QRadar SIEM Reference Sets and Reference Maps."""

    @classmethod
    def export_reference_set_csv(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 70.0,
    ) -> str:
        """Outputs a CSV compatible with QRadar Reference Set CLI import tool (ReferenceDataCLI)."""
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["Value", "Type", "ConfidenceScore", "Source"])

        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                ioc_type = item.get("type", "").lower()
                score = float(item.get("confidence_score", 0.0))
                source = item.get("source", "CTI-Engine")
                is_whitelisted = item.get("is_whitelisted", False)
            elif isinstance(item, IndicatorRead):
                norm_val = item.normalized_value
                ioc_type = item.type.value.lower()
                score = float(item.confidence_score)
                source = item.source
                is_whitelisted = bool(item.is_whitelisted)
            else:
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type).lower()
                score = float(item.confidence_score)
                source = getattr(item, "source", "CTI-Engine")
                is_whitelisted = bool(item.is_whitelisted)

            if is_whitelisted or score < min_score or not norm_val:
                continue

            writer.writerow([norm_val, ioc_type, f"{score:.1f}", source])

        return output.getvalue()

    @classmethod
    def export_reference_map_json(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 70.0,
    ) -> str:
        """Outputs QRadar REST API reference_data/map payload."""
        data_map: Dict[str, str] = {}
        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                score = float(item.get("confidence_score", 0.0))
                is_whitelisted = item.get("is_whitelisted", False)
            else:
                norm_val = str(item.normalized_value)
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)

            if is_whitelisted or score < min_score or not norm_val:
                continue

            data_map[norm_val] = f"{score:.1f}"

        return json.dumps(data_map, indent=2)
