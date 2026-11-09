"""Unit tests for Google Cloud Armor WAF security policy exporter."""

import json
from cti_core.exporters.google_cloud_armor_exporter import GoogleCloudArmorExporter


def test_google_cloud_armor_export():
    indicators = [
        {"normalized_value": "198.51.100.12", "type": "ipv4", "confidence_score": 92.0, "is_whitelisted": False},
        {"normalized_value": "2001:db8::dead", "type": "ipv6", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "8.8.4.4", "type": "ipv4", "confidence_score": 99.0, "is_whitelisted": True},
    ]

    out_json = GoogleCloudArmorExporter.export_policy_json(indicators, min_score=75.0)
    data = json.loads(out_json)

    assert data["type"] == "CLOUD_ARMOR"
    assert len(data["rules"]) == 1
    rule = data["rules"][0]
    assert rule["action"] == "deny(403)"
    assert "198.51.100.12/32" in rule["match"]["config"]["srcIpRanges"]
    assert "2001:db8::dead/128" in rule["match"]["config"]["srcIpRanges"]
    assert "8.8.4.4/32" not in rule["match"]["config"]["srcIpRanges"]
