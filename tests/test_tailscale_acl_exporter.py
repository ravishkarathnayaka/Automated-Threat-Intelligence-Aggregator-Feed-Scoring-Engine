"""Unit tests for Tailscale ACL exporter."""

import json
from cti_core.exporters.tailscale_acl_exporter import TailscaleAclExporter


def test_tailscale_acl_export():
    indicators = [
        {"normalized_value": "198.51.100.5", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "203.0.113.10", "type": "ipv4", "confidence_score": 80.0, "is_whitelisted": False},
        {"normalized_value": "100.64.0.1", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": True},
    ]

    out_json = TailscaleAclExporter.export_acl_json(indicators, min_score=75.0)
    data = json.loads(out_json)

    assert data["total_blocked_destinations"] == 2
    rule = data["acls"][0]
    assert rule["action"] == "drop"
    assert "198.51.100.5/32:*" in rule["dst"]
    assert "203.0.113.10/32:*" in rule["dst"]
    assert "100.64.0.1" not in out_json
