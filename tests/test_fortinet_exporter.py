"""Unit tests verifying Fortinet FortiGate threat feed export."""

from cti_core.exporters.fortinet_exporter import FortinetExporter


def test_fortinet_export_format():
    """Verify Fortinet IP export produces clean list excluding whitelisted assets."""
    indicators = [
        {
            "value": "185.220.101.5",
            "type": "ipv4",
            "confidence_score": 90.0,
            "is_whitelisted": False,
        },
        {
            "value": "194.26.29.112",
            "type": "ipv4",
            "confidence_score": 85.0,
            "is_whitelisted": False,
        },
        {
            "value": "8.8.8.8",
            "type": "ipv4",
            "confidence_score": 0.0,
            "is_whitelisted": True,
        },
    ]

    out = FortinetExporter.export_ip_feed(indicators, min_score=70.0)
    assert "# Fortinet FortiGate Threat Feed" in out
    assert "185.220.101.5" in out
    assert "194.26.29.112" in out
    assert "8.8.8.8" not in out
