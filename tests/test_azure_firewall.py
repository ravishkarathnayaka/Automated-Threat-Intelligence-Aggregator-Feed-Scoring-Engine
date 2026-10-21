"""Unit tests for Azure Firewall IP Groups exporter."""

import json
from cti_core.exporters.azure_firewall_exporter import AzureFirewallExporter


def test_azure_firewall_ip_groups():
    indicators = [
        {"normalized_value": "198.51.100.14", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": False},
        {"normalized_value": "198.51.100.14", "type": "ipv4", "confidence_score": 95.0, "is_whitelisted": False},  # duplicate
        {"normalized_value": "203.0.113.88", "type": "ipv4", "confidence_score": 50.0, "is_whitelisted": False},  # low score
        {"normalized_value": "1.1.1.1", "type": "ipv4", "confidence_score": 99.0, "is_whitelisted": True},  # whitelisted
        {"normalized_value": "2001:db8::cafe", "type": "ipv6", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "evil.xyz", "type": "domain", "confidence_score": 99.0, "is_whitelisted": False},
    ]

    arm = AzureFirewallExporter.export_ip_group(indicators, group_name="TestThreatIPs", min_score=75.0)
    assert arm["contentVersion"] == "1.0.0.0"
    res = arm["resources"][0]
    assert res["name"] == "TestThreatIPs"
    assert res["type"] == "Microsoft.Network/ipGroups"
    ips = res["properties"]["ipAddresses"]
    assert ips == ["198.51.100.14", "2001:db8::cafe"]

    json_str = AzureFirewallExporter.export_json(indicators, min_score=75.0)
    data = json.loads(json_str)
    assert data["resources"][0]["properties"]["ipAddresses"] == ["198.51.100.14", "2001:db8::cafe"]
