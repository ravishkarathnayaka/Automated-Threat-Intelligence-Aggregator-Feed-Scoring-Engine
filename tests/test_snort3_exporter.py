"""Unit tests for Snort 3 modern IPS rule exporter."""

from cti_core.exporters.snort3_exporter import Snort3Exporter


def test_snort3_rules_export():
    indicators = [
        {"normalized_value": "198.51.100.99", "type": "ipv4", "confidence_score": 88.0, "is_whitelisted": False},
        {"normalized_value": "phish-portal.cc", "type": "domain", "confidence_score": 82.0, "is_whitelisted": False},
        {"normalized_value": "127.0.0.1", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": True},
        {"normalized_value": "low.biz", "type": "domain", "confidence_score": 40.0, "is_whitelisted": False},
    ]

    rules = Snort3Exporter.export_rules(indicators, min_score=75.0)
    assert "reject ip $HOME_NET any -> 198.51.100.99 any" in rules
    assert "http_header:field host; content:\"phish-portal.cc\"" in rules
    assert "metadata:engine sentinel_cti" in rules
    assert "127.0.0.1" not in rules
    assert "low.biz" not in rules
