"""Elasticsearch and OpenSearch bulk NDJSON threat indicator index document exporter."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, Iterable, Union

from cti_core.models.indicator import IndicatorModel, IndicatorRead


class ElasticExporter:
    """Exports indicators in standard Elastic Common Schema (ECS) bulk index action NDJSON."""

    @classmethod
    def export_bulk_ndjson(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        index_name: str = "threat-intel-indicators",
        min_score: float = 70.0,
    ) -> str:
        """Export into Elasticsearch bulk API compliant newline-delimited JSON."""
        now_iso = datetime.now(timezone.utc).isoformat()
        lines = []

        for item in indicators:
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                ioc_type = item.get("type", "").lower()
                score = float(item.get("confidence_score", 0.0))
                is_whitelisted = item.get("is_whitelisted", False)
                tags = item.get("tags") or []
                sources = item.get("sources") or []
            elif isinstance(item, IndicatorRead):
                norm_val = item.normalized_value
                ioc_type = item.type.value.lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
                tags = list(item.tags or [])
                sources = list(item.sources or [])
            else:
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type).lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
                tags = list(item.tags or [])
                sources = list(item.sources or [])

            if is_whitelisted or score < min_score:
                continue

            clean_sources = [s.source_name if hasattr(s, "source_name") else str(s) for s in sources]
            clean_tags = [t.name if hasattr(t, "name") else str(t) for t in tags]

            doc_id = f"sentinel-{ioc_type}-{norm_val.replace('/', '_')}"
            action_line = {"index": {"_index": index_name, "_id": doc_id}}

            doc_line = {
                "@timestamp": now_iso,
                "threat": {
                    "indicator": {
                        "type": ioc_type,
                        "value": norm_val,
                        "confidence": int(score),
                    },
                    "feed": {
                        "name": "SENTINEL-CTI",
                        "sources": clean_sources,
                    },
                },
                "tags": clean_tags,
            }

            lines.append(json.dumps(action_line))
            lines.append(json.dumps(doc_line))

        return "\n".join(lines) + ("\n" if lines else "")
