"""Unit tests for YARA exporter."""

from cti_core.exporters.yara_exporter import YARAExporter


def test_yara_rule_generation():
    indicators = [
        {
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "type": "sha256",
            "confidence_score": 95.0,
            "is_whitelisted": False,
        },
        {
            "value": "d41d8cd98f00b204e9800998ecf8427e",
            "type": "md5",
            "confidence_score": 88.0,
            "is_whitelisted": False,
        },
        {
            "value": "198.51.100.1",
            "type": "ipv4",
            "confidence_score": 90.0,
            "is_whitelisted": False,
        },
        {
            "value": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "type": "sha1",
            "confidence_score": 60.0,  # below default 75.0
            "is_whitelisted": False,
        },
    ]

    output = YARAExporter.export_rules(indicators, rule_name="Custom_Malware_Threats", min_score=75.0)

    assert 'rule Custom_Malware_Threats' in output
    assert 'import "hash"' in output
    assert 'hash.sha256(0, filesize) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"' in output
    assert 'hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e"' in output
    assert 'da39a3ee5e6b4b0d3255bfef95601890afd80709' not in output  # low score


def test_yara_rule_empty_set():
    output = YARAExporter.export_rules([], rule_name="Empty_Rule")
    assert "rule Empty_Rule" in output
    assert "condition:\n        false" in output
