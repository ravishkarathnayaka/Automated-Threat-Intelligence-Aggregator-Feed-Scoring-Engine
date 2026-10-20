"""CSV and TSV formatted threat report exporter."""

import csv
import io
from typing import Any, Dict, Iterable, Union

from cti_core.models.indicator import IndicatorModel, IndicatorRead


class CSVExporter:
    """Exports threat indicators into standard CSV / TSV formats for SIEM ingestion."""

    HEADERS = [
        "indicator",
        "type",
        "confidence_score",
        "severity",
        "sources",
        "tags",
        "first_seen",
        "last_seen",
        "is_whitelisted",
    ]

    @classmethod
    def _get_severity(cls, score: float) -> str:
        if score >= 85.0:
            return "critical"
        if score >= 70.0:
            return "high"
        if score >= 50.0:
            return "medium"
        return "low"

    @classmethod
    def export(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        delimiter: str = ",",
        min_score: float = 0.0,
        exclude_whitelisted: bool = True,
    ) -> str:
        """Render indicators to a CSV/TSV formatted string."""
        output = io.StringIO()
        writer = csv.writer(output, delimiter=delimiter, lineterminator="\n")
        writer.writerow(cls.HEADERS)

        for item in indicators:
            if isinstance(item, dict):
                val = item.get("normalized_value") or item.get("value", "")
                itype = item.get("type", "")
                score = float(item.get("confidence_score", 0.0))
                sources = ";".join(item.get("sources") or [])
                tags = ";".join(item.get("tags") or [])
                f_seen = str(item.get("first_seen", ""))
                l_seen = str(item.get("last_seen", ""))
                whitelisted = bool(item.get("is_whitelisted", False))
            elif isinstance(item, IndicatorRead):
                val = item.normalized_value
                itype = item.type.value
                score = float(item.confidence_score)
                sources = ";".join(item.sources)
                tags = ";".join(item.tags)
                f_seen = item.first_seen.isoformat() if item.first_seen else ""
                l_seen = item.last_seen.isoformat() if item.last_seen else ""
                whitelisted = bool(item.is_whitelisted)
            else:  # IndicatorModel
                val = str(item.normalized_value)
                itype = str(item.type)
                score = float(item.confidence_score)
                sources = ";".join(item.sources or [])
                tags = ";".join(item.tags or [])
                f_seen = item.first_seen.isoformat() if item.first_seen else ""
                l_seen = item.last_seen.isoformat() if item.last_seen else ""
                whitelisted = bool(item.is_whitelisted)

            if exclude_whitelisted and whitelisted:
                continue
            if score < min_score:
                continue

            writer.writerow([
                val,
                itype,
                f"{score:.1f}",
                cls._get_severity(score),
                sources,
                tags,
                f_seen,
                l_seen,
                str(whitelisted),
            ])

        return output.getvalue()
