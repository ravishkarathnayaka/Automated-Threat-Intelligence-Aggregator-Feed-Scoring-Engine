"""Unit tests for SentinelOne Deep Visibility S1QL exporter."""

from cti_core.exporters.sentinelone_exporter import SentinelOneExporter


def test_sentinelone_query_generation():
    indicators = [
        {
            "value": "198.51.100.22",
            "type": "ipv4",
            "confidence_score": 90.0,
            "is_whitelisted": False,
        },
        {
            "value": "malware-c2.org",
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

    query = SentinelOneExporter.export_query(indicators, min_score=75.0)

    assert 'DstIP in ("198.51.100.22")' in query
    assert 'DNSRequest in ("malware-c2.org")' in query
    assert 'TgtFileSHA256 in ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")' in query


def test_sentinelone_empty_set():
    query = SentinelOneExporter.export_query([], min_score=75.0)
    assert "EventType = \"Process Creation\" and false" in query
