"""Unit tests for OpenSearch Security Analytics monitor exporter."""

import json
from cti_core.exporters.opensearch_monitor_exporter import OpenSearchMonitorExporter


def test_opensearch_monitor_export():
    indicators = [
        {"normalized_value": "198.51.100.88", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "malware-beacon.xyz", "type": "domain", "confidence_score": 88.0, "is_whitelisted": False},
        {"normalized_value": "1.1.1.1", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": True},
    ]

    out_json = OpenSearchMonitorExporter.export_monitor_query(
        indicators,
        index_pattern="vpc-flow-logs-*",
        min_score=75.0,
    )
    data = json.loads(out_json)

    assert data["name"] == "SENTINEL-CTI Threat Match Detector"
    assert data["type"] == "monitor"
    assert data["inputs"][0]["search"]["indices"] == ["vpc-flow-logs-*"]
    should_clauses = data["inputs"][0]["search"]["query"]["bool"]["should"]
    assert "198.51.100.88" in should_clauses[0]["terms"]["destination.ip.keyword"]
    assert "malware-beacon.xyz" in should_clauses[2]["terms"]["dns.question.name.keyword"]
    assert "1.1.1.1" not in out_json
