"""Unit tests for Kong API Gateway IP Restriction plugin exporter."""

import json
from cti_core.exporters.kong_gateway_exporter import KongGatewayExporter


def test_kong_gateway_export():
    indicators = [
        {"normalized_value": "198.51.100.200", "type": "ipv4", "confidence_score": 93.0, "is_whitelisted": False},
        {"normalized_value": "2001:db8::bad", "type": "ipv6", "confidence_score": 80.0, "is_whitelisted": False},
        {"normalized_value": "1.0.0.1", "type": "ipv4", "confidence_score": 99.0, "is_whitelisted": True},
    ]

    out_json = KongGatewayExporter.export_plugin_json(indicators, min_score=75.0)
    data = json.loads(out_json)

    assert data["name"] == "ip-restriction"
    assert data["enabled"] is True
    assert "198.51.100.200" in data["config"]["deny"]
    assert "2001:db8::bad" in data["config"]["deny"]
    assert "1.0.0.1" not in data["config"]["deny"]
