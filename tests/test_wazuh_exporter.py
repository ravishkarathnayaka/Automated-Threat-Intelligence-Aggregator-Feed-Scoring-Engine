"""Unit tests for Wazuh CDB list exporter."""

from cti_core.exporters.wazuh_exporter import WazuhExporter


def test_wazuh_cdb_export():
    indicators = [
        {
            "value": "198.51.100.22",
            "confidence_score": 90.0,
            "is_whitelisted": False,
        },
        {
            "value": "phishing.biz",
            "confidence_score": 75.0,
            "is_whitelisted": False,
        },
        {
            "value": "1.1.1.1",
            "confidence_score": 95.0,
            "is_whitelisted": True,
        },
    ]

    cdb = WazuhExporter.export_cdb(indicators, min_score=70.0)
    lines = [line.strip() for line in cdb.strip().split("\n")]

    assert len(lines) == 2
    assert "198.51.100.22:critical" in lines[0]
    assert "phishing.biz:high" in lines[1]
    assert "1.1.1.1" not in cdb
