"""Unit tests for Okta Identity Network Zone exporter."""

import json
from cti_core.exporters.okta_zone_exporter import OktaZoneExporter


def test_okta_zone_export():
    indicators = [
        {"normalized_value": "198.51.100.80", "type": "ipv4", "confidence_score": 88.0, "is_whitelisted": False},
        {"normalized_value": "203.0.113.0/24", "type": "ipv4", "confidence_score": 92.0, "is_whitelisted": False},
        {"normalized_value": "10.0.0.1", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": True},
    ]

    out_json = OktaZoneExporter.export_zone_json(
        indicators,
        zone_name="IAM-Adversary-Quarantine",
        min_score=75.0,
    )
    data = json.loads(out_json)

    assert data["type"] == "IP"
    assert data["usage"] == "BLOCKLIST"
    assert data["name"] == "IAM-Adversary-Quarantine"
    assert len(data["gateways"]) == 2
    assert data["gateways"][0]["value"] == "198.51.100.80/32"
    assert data["gateways"][1]["value"] == "203.0.113.0/24"
