"""Unit tests for CrowdStrike Falcon Data Replicator (FDR) query exporter."""

from cti_core.exporters.crowdstrike_fdr_exporter import CrowdStrikeFDRExporter


def test_crowdstrike_fdr_sql_generation():
    indicators = [
        {"normalized_value": "185.220.101.6", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "c2-hunting-gate.org", "type": "domain", "confidence_score": 90.0, "is_whitelisted": False},
        {"normalized_value": "127.0.0.1", "type": "ipv4", "confidence_score": 99.0, "is_whitelisted": True},
        {"normalized_value": "low.cc", "type": "domain", "confidence_score": 50.0, "is_whitelisted": False},
    ]

    sql = CrowdStrikeFDRExporter.generate_athena_sql(indicators, min_score=75.0)
    assert "event_simpleName = 'NetworkConnectIP4'" in sql
    assert "'185.220.101.6'" in sql
    assert "'c2-hunting-gate.org'" in sql
    assert "127.0.0.1" not in sql
    assert "low.cc" not in sql
