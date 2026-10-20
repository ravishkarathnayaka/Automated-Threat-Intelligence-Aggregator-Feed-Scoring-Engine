"""Suricata EVE JSON event log exporter for SIEM detection pipeline testing."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, Iterable, List, Union

from cti_core.models.indicator import IndicatorModel, IndicatorRead


class SuricataEVEExporter:
    """Generates standard Suricata EVE JSON alert records for SIEM integration verification."""

    @classmethod
    def export_events(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 75.0,
    ) -> List[Dict[str, Any]]:
        """Generate EVE alert JSON event dictionaries."""
        now_iso = datetime.now(timezone.utc).isoformat()
        events: List[Dict[str, Any]] = []
        sid_start = 2000001

        for idx, item in enumerate(indicators):
            if isinstance(item, dict):
                norm_val = item.get("normalized_value") or item.get("value", "")
                ioc_type = item.get("type", "")
                score = float(item.get("confidence_score", 0.0))
                is_whitelisted = item.get("is_whitelisted", False)
                tags = item.get("tags") or []
            elif isinstance(item, IndicatorRead):
                norm_val = item.normalized_value
                ioc_type = item.type.value
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
                tags = list(item.tags or [])
            else:
                norm_val = str(item.normalized_value)
                ioc_type = str(item.type)
                score = float(item.confidence_score)
                is_whitelisted = bool(item.is_whitelisted)
                tags = list(item.tags or [])

            if is_whitelisted or score < min_score:
                continue

            sid = sid_start + idx

            if ioc_type in ("ipv4", "ipv6"):
                event = {
                    "timestamp": now_iso,
                    "event_type": "alert",
                    "src_ip": "10.0.10.45",
                    "src_port": 49210 + (idx % 1000),
                    "dest_ip": norm_val,
                    "dest_port": 443,
                    "proto": "TCP",
                    "alert": {
                        "action": "blocked",
                        "gid": 1,
                        "signature_id": sid,
                        "rev": 1,
                        "signature": f"SENTINEL-CTI Outbound Connection to Malicious IP [{norm_val}]",
                        "category": "A Network Trojan was detected",
                        "severity": 1 if score >= 85.0 else 2,
                        "metadata": {"confidence_score": [str(score)], "tags": tags},
                    },
                }
                events.append(event)
            elif ioc_type == "domain":
                event = {
                    "timestamp": now_iso,
                    "event_type": "alert",
                    "src_ip": "10.0.10.45",
                    "src_port": 53120,
                    "dest_ip": "1.1.1.1",
                    "dest_port": 53,
                    "proto": "UDP",
                    "dns": {"type": "query", "rrname": norm_val, "rrtype": "A"},
                    "alert": {
                        "action": "allowed",
                        "gid": 1,
                        "signature_id": sid,
                        "rev": 1,
                        "signature": f"SENTINEL-CTI DNS Query to Malicious C2 Domain [{norm_val}]",
                        "category": "Domain Name Server activity",
                        "severity": 1,
                    },
                }
                events.append(event)

        return events

    @classmethod
    def export_jsonlines(
        cls,
        indicators: Iterable[Union[IndicatorModel, IndicatorRead, Dict[str, Any]]],
        min_score: float = 75.0,
    ) -> str:
        """Export as newline-delimited JSON (NDJSON) matching eve.json format."""
        events = cls.export_events(indicators, min_score=min_score)
        return "\n".join(json.dumps(e) for e in events)
