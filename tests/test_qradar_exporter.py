"""Unit tests for IBM QRadar exporter."""

import json
from cti_core.exporters.qradar_exporter import QRadarExporter


def test_qradar_reference_set_csv():
    indicators = [
        {"normalized_value": "198.51.100.33", "type": "ipv4", "confidence_score": 85.5, "source": "AlienVault", "is_whitelisted": False},
        {"normalized_value": "malicious.org", "type": "domain", "confidence_score": 90.0, "source": "URLhaus", "is_whitelisted": False},
        {"normalized_value": "192.168.1.1", "type": "ipv4", "confidence_score": 95.0, "source": "Internal", "is_whitelisted": True},
        {"normalized_value": "10.0.0.1", "type": "ipv4", "confidence_score": 40.0, "source": "Internal", "is_whitelisted": False},
    ]

    csv_data = QRadarExporter.export_reference_set_csv(indicators, min_score=70.0)
    lines = [line.strip() for line in csv_data.strip().split("\n")]
    assert lines[0] == "Value,Type,ConfidenceScore,Source"
    assert "198.51.100.33,ipv4,85.5,AlienVault" in lines
    assert "malicious.org,domain,90.0,URLhaus" in lines
    assert "192.168.1.1" not in csv_data
    assert "10.0.0.1" not in csv_data


def test_qradar_reference_map_json():
    indicators = [
        {"normalized_value": "198.51.100.33", "type": "ipv4", "confidence_score": 85.5, "is_whitelisted": False},
    ]
    json_data = QRadarExporter.export_reference_map_json(indicators, min_score=70.0)
    parsed = json.loads(json_data)
    assert parsed["198.51.100.33"] == "85.5"
