"""Unit tests for Azure Front Door WAF custom rule exporter."""

import json
from cti_core.exporters.azure_front_door_waf_exporter import AzureFrontDoorWAFExporter


def test_azure_front_door_waf_export():
    indicators = [
        {"normalized_value": "198.51.100.33", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": False},
        {"normalized_value": "203.0.113.88", "type": "ipv4", "confidence_score": 82.0, "is_whitelisted": False},
        {"normalized_value": "1.1.1.1", "type": "ipv4", "confidence_score": 98.0, "is_whitelisted": True},
    ]

    out_json = AzureFrontDoorWAFExporter.export_waf_rules_json(indicators, min_score=75.0)
    data = json.loads(out_json)

    assert data["policyName"] == "SentinelFrontDoorWAFPolicy"
    rule = data["customRules"][0]
    assert rule["action"] == "Block"
    assert "198.51.100.33/32" in rule["matchConditions"][0]["matchValue"]
    assert "203.0.113.88/32" in rule["matchConditions"][0]["matchValue"]
    assert "1.1.1.1/32" not in rule["matchConditions"][0]["matchValue"]
