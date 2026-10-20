"""Unit tests for Suricata EVE JSON exporter."""

import json
from cti_core.exporters.suricata_eve_exporter import SuricataEVEExporter


def test_suricata_eve_export():
    indicators = [
        {
            "value": "198.51.100.22",
            "type": "ipv4",
            "confidence_score": 90.0,
            "tags": ["cobalt-strike"],
            "is_whitelisted": False,
        },
        {
            "value": "c2-domain.biz",
            "type": "domain",
            "confidence_score": 80.0,
            "tags": ["phish"],
            "is_whitelisted": False,
        },
        {
            "value": "1.1.1.1",
            "type": "ipv4",
            "confidence_score": 95.0,
            "is_whitelisted": True,
        },
    ]

    events = SuricataEVEExporter.export_events(indicators, min_score=75.0)
    assert len(events) == 2

    ip_event = next(e for e in events if e.get("dest_ip") == "198.51.100.22")
    assert ip_event["event_type"] == "alert"
    assert ip_event["alert"]["action"] == "blocked"
    assert ip_event["alert"]["severity"] == 1

    dns_event = next(e for e in events if e.get("dns"))
    assert dns_event["dns"]["rrname"] == "c2-domain.biz"

    ndjson = SuricataEVEExporter.export_jsonlines(indicators, min_score=75.0)
    lines = [json.loads(line) for line in ndjson.strip().split("\n")]
    assert len(lines) == 2
