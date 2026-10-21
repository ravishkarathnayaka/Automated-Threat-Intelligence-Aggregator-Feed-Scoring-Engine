"""Unit tests for AWS Network Firewall exporter."""

import json
from cti_core.exporters.aws_network_firewall_exporter import AWSNetworkFirewallExporter


def test_aws_network_firewall_export():
    indicators = [
        {
            "normalized_value": "198.51.100.25",
            "type": "ipv4",
            "confidence_score": 92.0,
            "is_whitelisted": False,
        },
        {
            "normalized_value": "203.0.113.5",
            "type": "ipv4",
            "confidence_score": 40.0,  # Below threshold
            "is_whitelisted": False,
        },
        {
            "normalized_value": "192.0.2.1",
            "type": "ipv4",
            "confidence_score": 95.0,
            "is_whitelisted": True,  # Whitelisted
        },
        {
            "normalized_value": "2001:db8::1",
            "type": "ipv6",
            "confidence_score": 88.0,
            "is_whitelisted": False,
        },
        {
            "normalized_value": "malware.example.com",
            "type": "domain",  # Non-IP
            "confidence_score": 99.0,
            "is_whitelisted": False,
        },
    ]

    res = AWSNetworkFirewallExporter.export_rule_group(indicators, min_score=75.0)
    assert "RuleGroup" in res
    rg = res["RuleGroup"]
    assert rg["Type"] == "STATEFUL"
    rules = rg["RulesSource"]["StatefulRules"]
    assert len(rules) == 2

    destinations = [r["Header"]["Destination"] for r in rules]
    assert "198.51.100.25/32" in destinations
    assert "2001:db8::1/32" in destinations

    raw_json = AWSNetworkFirewallExporter.export_json(indicators, min_score=75.0)
    parsed = json.loads(raw_json)
    assert parsed["RuleGroup"]["RuleGroupName"] == "Sentinel-CTI-Blocklist"
