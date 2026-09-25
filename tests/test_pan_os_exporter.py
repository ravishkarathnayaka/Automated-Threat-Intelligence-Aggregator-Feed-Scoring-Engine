"""Unit tests verifying Palo Alto Networks (PAN-OS) XML category export."""

from cti_core.exporters.pan_os_exporter import PanOSExporter


def test_pan_os_xml_export_structure():
    """Verify PAN-OS XML output has valid structure and tags."""
    indicators = [
        {
            "value": "185.220.101.5",
            "type": "ipv4",
            "confidence_score": 90.0,
            "is_whitelisted": False,
        },
        {
            "value": "evil-phishing-gate.cc",
            "type": "domain",
            "confidence_score": 85.0,
            "is_whitelisted": False,
        },
        {
            "value": "http://evil-c2.cc/beacon",
            "type": "url",
            "confidence_score": 88.0,
            "is_whitelisted": False,
        },
        {
            "value": "8.8.8.8",
            "type": "ipv4",
            "confidence_score": 0.0,
            "is_whitelisted": True,
        },
    ]

    xml = PanOSExporter.export_edl_xml(indicators, category_name="SENTINEL-BLOCK", min_score=70.0)

    assert '<?xml version="1.0" encoding="UTF-8"?>' in xml
    assert '<custom-url-category name="SENTINEL-BLOCK">' in xml
    assert "<member>185.220.101.5</member>" in xml
    assert "<member>evil-phishing-gate.cc</member>" in xml
    assert "<member>http://evil-c2.cc/beacon</member>" in xml
    # Whitelisted items must be excluded
    assert "8.8.8.8" not in xml


def test_pan_os_xml_escaping():
    """Verify special XML characters in URLs are properly escaped."""
    indicators = [
        {
            "value": "https://malicious.org/search?q=1&param=2",
            "type": "url",
            "confidence_score": 80.0,
            "is_whitelisted": False,
        }
    ]

    xml = PanOSExporter.export_edl_xml(indicators, min_score=70.0)
    assert "<member>https://malicious.org/search?q=1&amp;param=2</member>" in xml
