"""Unit tests for VyOS firewall address-group exporter."""

from cti_core.exporters.brocade_vyos_exporter import VyOSExporter


def test_vyos_script_generation():
    indicators = [
        {"normalized_value": "198.51.100.123", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "2001:db8::1234", "type": "ipv6", "confidence_score": 80.0, "is_whitelisted": False},
        {"normalized_value": "192.168.1.1", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": True},
        {"normalized_value": "10.0.0.5", "type": "ipv4", "confidence_score": 40.0, "is_whitelisted": False},
    ]

    script = VyOSExporter.export_cli_script(indicators, group_name="TEST_GROUP", min_score=75.0)
    assert "set firewall group address-group TEST_GROUP description" in script
    assert "set firewall group address-group TEST_GROUP address '198.51.100.123'" in script
    assert "set firewall group address-group TEST_GROUP address '2001:db8::1234'" in script
    assert "192.168.1.1" not in script
    assert "10.0.0.5" not in script
