"""Unit tests for Zeek notice policy script exporter."""

from cti_core.exporters.bro_notice_exporter import ZeekNoticeExporter


def test_zeek_notice_script():
    indicators = [
        {"normalized_value": "198.51.100.11", "type": "ipv4", "confidence_score": 88.0, "is_whitelisted": False},
        {"normalized_value": "10.0.0.1", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": True},
        {"normalized_value": "203.0.113.5", "type": "ipv4", "confidence_score": 50.0, "is_whitelisted": False},
    ]

    script = ZeekNoticeExporter.export_script(indicators, min_score=80.0)
    assert "@load base/frameworks/notice" in script
    assert "198.51.100.11" in script
    assert "10.0.0.1" not in script
    assert "203.0.113.5" not in script
    assert "event connection_established" in script
