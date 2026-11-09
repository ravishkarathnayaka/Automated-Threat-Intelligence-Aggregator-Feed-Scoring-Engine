"""Unit tests for AWS WAFv2 IPSet JSON exporter."""

import json
from cti_core.exporters.aws_wafv2_exporter import AWSWAFv2Exporter


def test_aws_wafv2_export():
    indicators = [
        {"normalized_value": "198.51.100.88", "type": "ipv4", "confidence_score": 89.0, "is_whitelisted": False},
        {"normalized_value": "203.0.113.100", "type": "ipv4", "confidence_score": 78.0, "is_whitelisted": False},
        {"normalized_value": "1.1.1.1", "type": "ipv4", "confidence_score": 99.0, "is_whitelisted": True},
    ]

    out_json = AWSWAFv2Exporter.export_ipset_json(indicators, scope="CLOUDFRONT", min_score=75.0)
    data = json.loads(out_json)

    assert data["Scope"] == "CLOUDFRONT"
    assert data["IPAddressVersion"] == "IPV4"
    assert "198.51.100.88/32" in data["Addresses"]
    assert "203.0.113.100/32" in data["Addresses"]
    assert "1.1.1.1/32" not in data["Addresses"]
