"""Unit tests for Splunk lookup table exporter."""

from cti_core.exporters.splunk_lookup_exporter import SplunkLookupExporter


def test_splunk_lookup_csv():
    indicators = [
        {"normalized_value": "198.51.100.44", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": False, "tags": ["c2-scanner"]},
        {"normalized_value": "evil-domain.com", "type": "domain", "confidence_score": 92.5, "is_whitelisted": False, "tags": ["apt29"]},
        {"normalized_value": "1.1.1.1", "type": "ipv4", "confidence_score": 99.0, "is_whitelisted": True, "tags": ["dns"]},
        {"normalized_value": "low.com", "type": "domain", "confidence_score": 40.0, "is_whitelisted": False},
    ]

    csv_data = SplunkLookupExporter.export_csv(indicators, min_score=65.0)
    lines = [line.strip() for line in csv_data.strip().split("\n")]
    assert lines[0] == "threat_key,indicator,type,confidence,threat_category,weight,description"
    assert len(lines) == 3
    assert "198.51.100.44,ipv4,85.0,c2-scanner,8.5,SENTINEL-CTI confidence: 85.0" in lines[1]
    assert "evil-domain.com,domain,92.5,apt29,9.2,SENTINEL-CTI confidence: 92.5" in lines[2]
    assert "1.1.1.1" not in csv_data
