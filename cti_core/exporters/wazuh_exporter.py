"""Wazuh SIEM CDB list threat indicator exporter."""

from typing import Any, Dict, Iterable, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class WazuhExporter:
    """Exports indicators into Wazuh Constant Database (CDB) key:value list format."""

    @classmethod
    def _get_severity(cls, score: float) -> str:
        if score >= 85.0:
            return "critical"
        if score >= 70.0:
            return "high"
        if score >= 40.0:
            return "medium"
        return "low"

    @classmethod
    def export_cdb(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 70.0,
    ) -> str:
        """Export as key:value lines compatible with Wazuh ossec.conf <list> directives."""
        lines = []
        seen = set()

        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                score = float(item.get("confidence_score", 0.0))
                is_whitelisted = item.get("is_whitelisted", False)
            elif isinstance(item, IndicatorRead):
                norm_val = item.normalized_value
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
            else:
                norm_val = str(item.normalized_value)
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)

            if is_whitelisted or score < min_score:
                continue

            if norm_val not in seen:
                seen.add(norm_val)
                lines.append(f"{norm_val}:{cls._get_severity(score)}")

        return "\n".join(lines) + ("\n" if lines else "")
