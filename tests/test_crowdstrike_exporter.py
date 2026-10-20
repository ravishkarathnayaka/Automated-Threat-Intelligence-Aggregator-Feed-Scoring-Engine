"""Unit tests for CrowdStrike Falcon Custom IOC CSV exporter."""

from cti_core.exporters.crowdstrike_exporter import CrowdStrikeExporter


def test_crowdstrike_export_format():
    indicators = [
        {
            "value": "198.51.100.22",
            "type": "ipv4",
            "confidence_score": 90.0,
            "is_whitelisted": False,
        },
        {
            "value": "phishing-bank.biz",
            "type": "domain",
            "confidence_score": 75.0,
            "is_whitelisted": False,
        },
        {
            "value": "1.1.1.1",
            "type": "ipv4",
            "confidence_score": 90.0,
            "is_whitelisted": True,
        },
        {
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "type": "sha256",
            "confidence_score": 95.0,
            "is_whitelisted": False,
        },
    ]

    csv_data = CrowdStrikeExporter.export(indicators, min_score=70.0)
    lines = [line.strip() for line in csv_data.strip().split("\n")]

    assert lines[0] == "type,value,action,severity,description"
    assert len(lines) == 4  # Header + 3 non-whitelisted items >= 70.0

    # 90.0 score -> prevent, critical
    assert "ipv4,198.51.100.22,prevent,critical" in lines[1]
    # 75.0 score -> detect, high
    assert "domain,phishing-bank.biz,detect,high" in lines[2]
    # sha256 -> prevent, critical
    assert "sha256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,prevent,critical" in lines[3]
