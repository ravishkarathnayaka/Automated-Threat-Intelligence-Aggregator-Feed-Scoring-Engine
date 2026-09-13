"""Deduplication and multi-source indicator record merger."""

from datetime import datetime, timezone
from typing import Any, Dict, List

from cti_core.models.indicator import SeverityLevel

SEVERITY_ORDER = {
    SeverityLevel.INFO.value: 0,
    SeverityLevel.LOW.value: 1,
    SeverityLevel.MEDIUM.value: 2,
    SeverityLevel.HIGH.value: 3,
    SeverityLevel.CRITICAL.value: 4,
}


def parse_timestamp(val: Any) -> datetime:
    """Safely parse various datetime formats to a UTC datetime object."""
    if isinstance(val, datetime):
        return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            pass
    return datetime.now(timezone.utc)


class Deduplicator:
    """Deduplicates incoming raw indicator records and merges multi-feed sightings."""

    @staticmethod
    def deduplicate_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group and merge indicator records by (type, normalized_value)."""
        grouped: Dict[str, Dict[str, Any]] = {}

        for rec in records:
            ioc_type = rec.get("type")
            norm_val = rec.get("normalized_value") or rec.get("value")
            if not norm_val or not ioc_type:
                continue

            # Standardize type string
            type_key = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type).lower()
            norm_key = f"{type_key}:{norm_val}"

            reported_dt = parse_timestamp(rec.get("reported_at"))
            source_name = rec.get("source", "unknown")
            source_conf = rec.get("reported_confidence", 50.0)
            ref_url = rec.get("reference_url")
            tags = list(rec.get("tags") or [])
            severity = rec.get("severity", SeverityLevel.MEDIUM.value)
            if hasattr(severity, "value"):
                severity = severity.value

            source_entry = {
                "source_name": source_name,
                "confidence": source_conf,
                "reported_at": reported_dt,
                "reference_url": ref_url,
                "raw_tags": tags,
                "source_weight": rec.get("source_weight", 0.7),
            }

            if norm_key not in grouped:
                grouped[norm_key] = {
                    "value": rec.get("value", norm_val),
                    "normalized_value": norm_val,
                    "type": type_key,
                    "first_seen": reported_dt,
                    "last_seen": reported_dt,
                    "severity": severity,
                    "tags": set(tags),
                    "sources": [source_entry],
                    "raw_metadata": rec.get("raw_metadata") or {},
                }
            else:
                existing = grouped[norm_key]
                # Update first / last seen
                if reported_dt < existing["first_seen"]:
                    existing["first_seen"] = reported_dt
                if reported_dt > existing["last_seen"]:
                    existing["last_seen"] = reported_dt

                # Merge tags
                existing["tags"].update(tags)

                # Escalate severity if new record has higher severity
                curr_sev_rank = SEVERITY_ORDER.get(existing["severity"], 2)
                new_sev_rank = SEVERITY_ORDER.get(severity, 2)
                if new_sev_rank > curr_sev_rank:
                    existing["severity"] = severity

                # Append source if distinct or update if already present
                existing_sources = existing["sources"]
                matched_source = next((s for s in existing_sources if s["source_name"] == source_name), None)
                if not matched_source:
                    existing_sources.append(source_entry)
                else:
                    if reported_dt > matched_source["reported_at"]:
                        matched_source["reported_at"] = reported_dt
                    matched_source["raw_tags"] = list(set(matched_source["raw_tags"] + tags))

        # Format final records
        merged_list = []
        for item in grouped.values():
            item["tags"] = sorted(list(item["tags"]))
            merged_list.append(item)

        return merged_list
