"""Unit tests for Microsoft Sentinel KQL query exporter."""

from cti_core.exporters.microsoft_sentinel_exporter import MicrosoftSentinelExporter


def test_kql_export_with_indicators():
    indicators = [
        {
            "value": "198.51.100.22",
            "type": "ipv4",
            "confidence_score": 85.0,
            "is_whitelisted": False,
        },
        {
            "value": "apt-c2.org",
            "type": "domain",
            "confidence_score": 90.0,
            "is_whitelisted": False,
        },
    ]

    kql = MicrosoftSentinelExporter.export_kql(indicators, min_score=75.0)

    assert "let BlocklistIPs = dynamic([" in kql
    assert '"198.51.100.22"' in kql
    assert "CommonSecurityLog" in kql
    assert "let MaliciousDomains = dynamic([" in kql
    assert '"apt-c2.org"' in kql
    assert "DnsEvents" in kql


def test_kql_empty_export():
    kql = MicrosoftSentinelExporter.export_kql([], min_score=75.0)
    assert "No active threats" in kql
