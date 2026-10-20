"""Unit tests for CSV/TSV threat report exporter."""

from cti_core.exporters.csv_exporter import CSVExporter


def test_csv_export_format():
    indicators = [
        {
            "value": "198.51.100.4",
            "type": "ipv4",
            "confidence_score": 95.0,
            "sources": ["abuseipdb", "threatfox"],
            "tags": ["c2"],
            "is_whitelisted": False,
        },
        {
            "value": "phish-test.xyz",
            "type": "domain",
            "confidence_score": 75.0,
            "sources": ["openphish"],
            "tags": ["credential-theft"],
            "is_whitelisted": False,
        },
        {
            "value": "8.8.8.8",
            "type": "ipv4",
            "confidence_score": 0.0,
            "sources": ["manual"],
            "is_whitelisted": True,
        },
    ]

    csv_data = CSVExporter.export(indicators, delimiter=",", min_score=50.0, exclude_whitelisted=True)
    lines = [line.strip() for line in csv_data.strip().split("\n")]

    assert lines[0] == "indicator,type,confidence_score,severity,sources,tags,first_seen,last_seen,is_whitelisted"
    assert len(lines) == 3  # Header + 2 non-whitelisted items above 50.0

    assert "198.51.100.4,ipv4,95.0,critical,abuseipdb;threatfox,c2" in lines[1]
    assert "phish-test.xyz,domain,75.0,high,openphish,credential-theft" in lines[2]
    assert "8.8.8.8" not in csv_data


def test_tsv_export_format():
    indicators = [
        {
            "value": "evil.com",
            "type": "domain",
            "confidence_score": 60.0,
            "sources": ["feodo"],
            "tags": [],
            "is_whitelisted": False,
        }
    ]

    tsv_data = CSVExporter.export(indicators, delimiter="\t", min_score=50.0)
    assert "\t" in tsv_data
    assert "evil.com\tdomain\t60.0\tmedium\tfeodo\t" in tsv_data
