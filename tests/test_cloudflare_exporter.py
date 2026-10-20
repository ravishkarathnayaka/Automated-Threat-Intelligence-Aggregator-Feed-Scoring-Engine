"""Unit tests verifying Cloudflare WAF IP Access Rule JSON generation."""

from cti_core.exporters.cloudflare_exporter import CloudflareWAFExporter


def test_cloudflare_waf_export():
    """Verify Cloudflare access rule JSON schema and target classification."""
    indicators = [
        {
            "value": "185.220.101.5",
            "type": "ipv4",
            "confidence_score": 92.0,
            "is_whitelisted": False,
        },
        {
            "value": "2606:4700::1",
            "type": "ipv6",
            "confidence_score": 85.0,
            "is_whitelisted": False,
        },
        {
            "value": "10.0.0.1",
            "type": "ipv4",
            "confidence_score": 0.0,
            "is_whitelisted": True,
        },
    ]

    rules = CloudflareWAFExporter.export_access_rules(indicators, min_score=70.0, mode="block")
    assert len(rules) == 2
    assert rules[0]["mode"] == "block"
    assert rules[0]["configuration"]["target"] == "ip"
    assert rules[0]["configuration"]["value"] == "185.220.101.5"

    assert rules[1]["configuration"]["target"] == "ip6"
    assert rules[1]["configuration"]["value"] == "2606:4700::1"
