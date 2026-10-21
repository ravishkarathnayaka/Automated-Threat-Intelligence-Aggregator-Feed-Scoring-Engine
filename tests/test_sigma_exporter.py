"""Unit tests for Sigma generic detection rule exporter."""

from cti_core.exporters.sigma_exporter import SigmaExporter


def test_sigma_network_rule_generation():
    indicators = [
        {"normalized_value": "185.220.101.5", "type": "ipv4", "confidence_score": 88.0, "is_whitelisted": False},
        {"normalized_value": "apt-c2-node.biz", "type": "domain", "confidence_score": 94.0, "is_whitelisted": False},
        {"normalized_value": "192.168.1.50", "type": "ipv4", "confidence_score": 95.0, "is_whitelisted": True},
        {"normalized_value": "lowconfidence.com", "type": "domain", "confidence_score": 45.0, "is_whitelisted": False},
    ]

    rule = SigmaExporter.generate_network_rule(indicators, min_score=80.0)
    assert "title: Automated CTI Engine High Confidence Malicious Communication" in rule
    assert "category: network_connection" in rule
    assert "- '185.220.101.5'" in rule
    assert "- 'apt-c2-node.biz'" in rule
    assert "192.168.1.50" not in rule
    assert "lowconfidence.com" not in rule
    assert "condition: selection_ip or selection_dns" in rule
