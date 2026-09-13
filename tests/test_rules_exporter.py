"""Unit tests verifying Suricata and Snort rule generation."""

from cti_core.exporters.rules_exporter import RulesExporter


def test_suricata_rules_generation():
    """Verify Suricata rules export correctly with proper syntax and SIDs."""
    indicators = [
        {"type": "ipv4", "normalized_value": "185.220.101.5", "confidence_score": 90.0, "is_whitelisted": False},
        {"type": "domain", "normalized_value": "c2.darknet-ops.cc", "confidence_score": 85.0, "is_whitelisted": False},
        {"type": "ipv4", "normalized_value": "8.8.8.8", "confidence_score": 90.0, "is_whitelisted": True},  # Whitelisted
        {"type": "ipv4", "normalized_value": "194.26.29.112", "confidence_score": 50.0, "is_whitelisted": False},  # Low score
    ]

    rules = RulesExporter.export_suricata(indicators, start_sid=1000001, min_score=75.0)

    # Malicious IP rule present
    assert 'alert ip any any -> 185.220.101.5 any' in rules
    assert 'sid:1000001;' in rules

    # Malicious domain TLS SNI rule present
    assert 'alert tls $HOME_NET any -> $EXTERNAL_NET any' in rules
    assert 'content:"c2.darknet-ops.cc";' in rules
    assert 'sid:1000002;' in rules

    # Whitelisted 8.8.8.8 not present
    assert "8.8.8.8" not in rules

    # Low score 194.26.29.112 not present
    assert "194.26.29.112" not in rules


def test_snort_rules_generation():
    """Verify Snort rules export properly."""
    indicators = [
        {"type": "ipv4", "normalized_value": "185.220.101.5", "confidence_score": 95.0, "is_whitelisted": False},
    ]

    rules = RulesExporter.export_snort(indicators, start_sid=2000001, min_score=75.0)
    assert 'alert ip any any -> 185.220.101.5 any' in rules
    assert 'sid:2000001;' in rules
