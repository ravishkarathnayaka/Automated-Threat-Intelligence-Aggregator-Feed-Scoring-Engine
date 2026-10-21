"""Unit tests for Cisco Umbrella exporter."""

from cti_core.exporters.opendns_umbrella_exporter import OpenDNSUmbrellaExporter


def test_umbrella_destination_list_and_csv():
    indicators = [
        {"normalized_value": "c2-domain.com", "type": "domain", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "198.51.100.99", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": False},
        {"normalized_value": "https://badphish.com/login", "type": "url", "confidence_score": 82.0, "is_whitelisted": False},
        {"normalized_value": "whitelisted.com", "type": "domain", "confidence_score": 90.0, "is_whitelisted": True},
        {"normalized_value": "low.com", "type": "domain", "confidence_score": 50.0, "is_whitelisted": False},
    ]

    destinations = OpenDNSUmbrellaExporter.export_destination_list(indicators, min_score=75.0)
    assert len(destinations) == 3
    assert destinations[0]["destination"] == "c2-domain.com"
    assert destinations[0]["type"] == "domain"
    assert destinations[1]["destination"] == "198.51.100.99"
    assert destinations[1]["type"] == "ipv4"
    assert destinations[2]["destination"] == "https://badphish.com/login"
    assert destinations[2]["type"] == "url"

    csv_data = OpenDNSUmbrellaExporter.export_csv(indicators, min_score=75.0)
    lines = csv_data.strip().split("\n")
    assert lines[0] == "destination,type,comment"
    assert len(lines) == 4
    assert "c2-domain.com,domain,Automated CTI Engine (score: 85.0)" in lines
