"""Unit tests verifying Check Point Security Gateway custom feed export."""

from cti_core.exporters.checkpoint_exporter import CheckPointExporter


def test_checkpoint_export_format():
    """Verify Check Point export generates valid semicolon comments and IP lines."""
    indicators = [
        {
            "value": "185.220.101.5",
            "type": "ipv4",
            "confidence_score": 92.0,
            "is_whitelisted": False,
            "tags": ["tor-exit", "mozi"],
        },
        {
            "value": "8.8.8.8",
            "type": "ipv4",
            "confidence_score": 0.0,
            "is_whitelisted": True,
        },
        {
            "value": "malware.exe",
            "type": "sha256",
            "confidence_score": 90.0,
            "is_whitelisted": False,
        },
    ]

    out = CheckPointExporter.export_blocklist(indicators, min_score=70.0)
    assert "; Check Point Custom Intelligence Feed" in out
    assert "185.220.101.5 ; Confidence: 92.0" in out
    # 8.8.8.8 whitelisted -> not present
    assert "8.8.8.8" not in out
    # Non-IP -> not present
    assert "malware.exe" not in out
