"""Unit tests verifying Zeek Intelligence Framework formatting and typing."""

from cti_core.exporters.zeek_exporter import ZeekIntelExporter


def test_zeek_exporter_mapping():
    """Verify indicators map to appropriate Intel::Type enum."""
    indicators = [
        {
            "value": "185.220.101.5",
            "type": "ipv4",
            "confidence_score": 92.0,
            "is_whitelisted": False,
            "tags": ["tor-exit", "mozi"],
        },
        {
            "value": "evil-c2-payload.cc",
            "type": "domain",
            "confidence_score": 88.0,
            "is_whitelisted": False,
            "tags": ["c2"],
        },
        {
            "value": "http://evil-c2-payload.cc/malware.exe",
            "type": "url",
            "confidence_score": 85.0,
            "is_whitelisted": False,
            "tags": ["stealer"],
        },
        {
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "type": "sha256",
            "confidence_score": 80.0,
            "is_whitelisted": False,
            "tags": ["dropper"],
        },
        {
            "value": "8.8.8.8",
            "type": "ipv4",
            "confidence_score": 0.0,
            "is_whitelisted": True,
            "tags": ["google-dns"],
        },
    ]

    output = ZeekIntelExporter.export_intel(indicators, min_score=70.0)

    # Header check
    assert "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.confidence" in output

    # Indicator checks
    assert "185.220.101.5\tIntel::ADDR\tSENTINEL_CTI" in output
    assert "evil-c2-payload.cc\tIntel::DOMAIN\tSENTINEL_CTI" in output
    assert "http://evil-c2-payload.cc/malware.exe\tIntel::URL\tSENTINEL_CTI" in output
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\tIntel::FILE_HASH\tSENTINEL_CTI" in output

    # Whitelisted check (should be filtered out)
    assert "8.8.8.8" not in output


def test_zeek_exporter_threshold_filtering():
    """Verify indicators below minimum score threshold are filtered out."""
    indicators = [
        {
            "value": "45.33.32.156",
            "type": "ipv4",
            "confidence_score": 65.0,
            "is_whitelisted": False,
        },
        {
            "value": "194.26.29.112",
            "type": "ipv4",
            "confidence_score": 85.0,
            "is_whitelisted": False,
        },
    ]

    output = ZeekIntelExporter.export_intel(indicators, min_score=70.0)
    assert "194.26.29.112" in output
    assert "45.33.32.156" not in output
