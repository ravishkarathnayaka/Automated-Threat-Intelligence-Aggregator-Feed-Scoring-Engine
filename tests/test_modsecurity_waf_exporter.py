"""Unit tests for ModSecurity WAF exporter."""

from cti_core.exporters.modsecurity_waf_exporter import ModSecurityWAFExporter


def test_modsecurity_export():
    indicators = [
        {"normalized_value": "198.51.100.44", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "malicious-phish.biz", "type": "domain", "confidence_score": 88.0, "is_whitelisted": False},
        {"normalized_value": "127.0.0.1", "type": "ipv4", "confidence_score": 99.0, "is_whitelisted": True},
    ]

    out_rules = ModSecurityWAFExporter.export_secrules(
        indicators,
        start_id=2200000,
        min_score=75.0,
    )

    assert 'SecRule REMOTE_ADDR "@ipMatch 198.51.100.44" "id:2200000,phase:1,deny,status:403' in out_rules
    assert 'SecRule REQUEST_HEADERS:Host "@streq malicious-phish.biz" "id:2200001,phase:1,deny,status:403' in out_rules
    assert "127.0.0.1" not in out_rules
