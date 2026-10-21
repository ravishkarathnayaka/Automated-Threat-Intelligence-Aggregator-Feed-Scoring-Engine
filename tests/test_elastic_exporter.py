"""Unit tests for Elasticsearch bulk NDJSON exporter."""

import json
from cti_core.exporters.elastic_exporter import ElasticExporter


def test_elastic_bulk_export():
    indicators = [
        {
            "value": "198.51.100.22",
            "type": "ipv4",
            "confidence_score": 90.0,
            "tags": ["cobalt-strike"],
            "sources": ["abuseipdb"],
            "is_whitelisted": False,
        },
        {
            "value": "1.1.1.1",
            "type": "ipv4",
            "confidence_score": 90.0,
            "is_whitelisted": True,
        },
    ]

    ndjson = ElasticExporter.export_bulk_ndjson(indicators, min_score=70.0)
    lines = [json.loads(line) for line in ndjson.strip().split("\n")]

    # 1 valid indicator -> 1 action line + 1 doc line = 2 lines
    assert len(lines) == 2
    assert lines[0]["index"]["_index"] == "threat-intel-indicators"
    assert lines[0]["index"]["_id"] == "sentinel-ipv4-198.51.100.22"
    assert lines[1]["threat"]["indicator"]["value"] == "198.51.100.22"
    assert lines[1]["threat"]["indicator"]["confidence"] == 90
