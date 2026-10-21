"""Unit tests for Carbon Black Cloud exporter."""

from cti_core.exporters.carbon_black_exporter import CarbonBlackExporter


def test_carbon_black_watchlist():
    indicators = [
        {
            "value": "198.51.100.22",
            "type": "ipv4",
            "confidence_score": 90.0,
            "is_whitelisted": False,
        },
        {
            "value": "c2-domain.org",
            "type": "domain",
            "confidence_score": 85.0,
            "is_whitelisted": False,
        },
        {
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "type": "sha256",
            "confidence_score": 95.0,
            "is_whitelisted": False,
        },
    ]

    wl = CarbonBlackExporter.export_watchlist(indicators, min_score=75.0)
    assert "feedinfo" in wl
    assert "reports" in wl
    iocs = wl["reports"][0]["iocs"]
    assert "198.51.100.22" in iocs["ipv4"]
    assert "c2-domain.org" in iocs["dns"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs["sha256"]
