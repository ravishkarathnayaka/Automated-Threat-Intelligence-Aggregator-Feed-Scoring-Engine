"""Unit tests for Datadog Cloud SIEM reference table exporter."""

import json
from cti_core.exporters.datadog_siem_exporter import DatadogSIEMExporter


def test_datadog_siem_export():
    indicators = [
        {"normalized_value": "198.51.100.75", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": False},
        {"normalized_value": "apt-stage.evil.cc", "type": "domain", "confidence_score": 76.0, "is_whitelisted": False},
        {"normalized_value": "8.8.8.8", "type": "ipv4", "confidence_score": 99.0, "is_whitelisted": True},
    ]

    out_json = DatadogSIEMExporter.export_reference_table_json(indicators, min_score=70.0)
    data = json.loads(out_json)

    assert data["table_name"] == "sentinel_cti_threat_indicators"
    assert len(data["rows"]) == 2
    assert data["rows"][0]["indicator"] == "198.51.100.75"
    assert data["rows"][0]["severity"] == "critical"
    assert data["rows"][1]["severity"] == "high"
