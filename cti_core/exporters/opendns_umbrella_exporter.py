"""Cisco Umbrella (OpenDNS) destination blocklist exporter."""

import csv
import io
import json
from typing import Any, Dict, Iterable, List, Union
from cti_core.models.indicator import IndicatorModel, IndicatorRead


class OpenDNSUmbrellaExporter:
    """Exports malicious domains and IPs to Cisco Umbrella destination lists."""

    @classmethod
    def export_destination_list(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 75.0,
    ) -> List[Dict[str, str]]:
        """Exports JSON payload compatible with Cisco Umbrella Destination Lists API."""
        destinations: List[Dict[str, str]] = []
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

            if is_whitelisted or score < min_score or not norm_val or norm_val in seen:
                continue

            if ioc_type in ("domain", "ipv4", "url"):
                seen.add(norm_val)
                destinations.append({
                    "destination": norm_val,
                    "type": "domain" if ioc_type == "domain" else ("ipv4" if ioc_type == "ipv4" else "url"),
                    "comment": f"Automated CTI Engine (score: {score:.1f})",
                })

        return destinations

    @classmethod
    def export_csv(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 75.0,
    ) -> str:
        """Exports Umbrella destination list CSV format (destination,comment)."""
        dests = cls.export_destination_list(indicators, min_score=min_score)
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["destination", "type", "comment"])
        for d in dests:
            writer.writerow([d["destination"], d["type"], d["comment"]])
        return buf.getvalue()
