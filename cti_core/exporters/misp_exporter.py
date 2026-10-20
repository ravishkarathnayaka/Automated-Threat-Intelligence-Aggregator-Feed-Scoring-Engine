"""MISP (Malware Information Sharing Platform) JSON event exporter."""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Union
import uuid

from cti_core.models.indicator import IndicatorModel, IndicatorRead


class MISPExporter:
    """Exports scored indicators into standardized MISP event and attribute JSON structure."""

    TYPE_MAP = {
        "ipv4": "ip-dst",
        "ipv6": "ip-dst",
        "domain": "domain",
        "url": "url",
        "sha256": "sha256",
        "sha1": "sha1",
        "md5": "md5",
    }

    @classmethod
    def export_event(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        event_info: str = "SENTINEL-CTI High-Confidence Threat Feed Export",
        min_score: float = 70.0,
    ) -> Dict[str, Any]:
        """Generate MISP Event object with Attribute list."""
        now = datetime.now(timezone.utc)
        attributes: List[Dict[str, Any]] = []
        seen = set()

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
            else:  # IndicatorModel
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type).lower()
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
                tags = list(item.tags or [])

            if is_whitelisted or score < min_score:
                continue

            misp_type = cls.TYPE_MAP.get(ioc_type)
            if not misp_type or norm_val in seen:
                continue
            seen.add(norm_val)

            attributes.append({
                "uuid": str(uuid.uuid4()),
                "type": misp_type,
                "category": "Network activity" if "ip" in misp_type or "domain" in misp_type or "url" in misp_type else "Payload delivery",
                "to_ids": True,
                "value": norm_val,
                "comment": f"Confidence Score: {score:.1f}",
                "timestamp": str(int(now.timestamp())),
                "Tag": [{"name": f"sentinel:{t}"} for t in tags[:3]],
            })

        return {
            "Event": {
                "uuid": str(uuid.uuid4()),
                "info": event_info,
                "threat_level_id": "1",  # High
                "analysis": "2",        # Completed
                "date": now.strftime("%Y-%m-%d"),
                "timestamp": str(int(now.timestamp())),
                "published": True,
                "Attribute": attributes,
            }
        }
