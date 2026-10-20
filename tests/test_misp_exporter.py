"""Unit tests for MISP exporter."""

from cti_core.exporters.misp_exporter import MISPExporter


def test_misp_export_structure():
    indicators = [
        {
            "value": "198.51.100.22",
            "normalized_value": "198.51.100.22",
            "type": "ipv4",
            "confidence_score": 85.0,
            "is_whitelisted": False,
            "tags": ["c2", "cobalt-strike"],
        },
        {
            "value": "malicious-apt.org",
            "normalized_value": "malicious-apt.org",
            "type": "domain",
            "confidence_score": 92.0,
            "is_whitelisted": False,
            "tags": ["phishing"],
        },
        {
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "normalized_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "type": "sha256",
            "confidence_score": 98.0,
            "is_whitelisted": False,
            "tags": ["ransomware"],
        },
        {
            "value": "1.1.1.1",
            "normalized_value": "1.1.1.1",
            "type": "ipv4",
            "confidence_score": 90.0,
            "is_whitelisted": True,  # whitelisted
        },
        {
            "value": "198.51.100.99",
            "normalized_value": "198.51.100.99",
            "type": "ipv4",
            "confidence_score": 45.0,  # below min_score
            "is_whitelisted": False,
        },
    ]

    event_payload = MISPExporter.export_event(indicators, min_score=70.0)

    assert "Event" in event_payload
    event = event_payload["Event"]
    assert event["threat_level_id"] == "1"
    assert event["published"] is True
    assert len(event["Attribute"]) == 3

    types = [attr["type"] for attr in event["Attribute"]]
    assert "ip-dst" in types
    assert "domain" in types
    assert "sha256" in types

    ip_attr = next(a for a in event["Attribute"] if a["type"] == "ip-dst")
    assert ip_attr["value"] == "198.51.100.22"
    assert any("cobalt-strike" in tag["name"] for tag in ip_attr["Tag"])
