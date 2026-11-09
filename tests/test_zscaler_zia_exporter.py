"""Unit tests for Zscaler ZIA custom URL category exporter."""

import json
from cti_core.exporters.zscaler_zia_exporter import ZscalerZIAExporter


def test_zscaler_zia_export():
    indicators = [
        {"normalized_value": "https://phishing-login.xyz/auth", "type": "url", "confidence_score": 89.0, "is_whitelisted": False},
        {"normalized_value": "203.0.113.77", "type": "ipv4", "confidence_score": 82.0, "is_whitelisted": False},
        {"normalized_value": "microsoft.com", "type": "domain", "confidence_score": 95.0, "is_whitelisted": True},
    ]

    out_json = ZscalerZIAExporter.export_zia_category_json(indicators, min_score=75.0)
    data = json.loads(out_json)

    assert data["id"] == "CUSTOM_01"
    assert data["customCategory"] is True
    assert "phishing-login.xyz/auth" in data["urls"]
    assert "203.0.113.77" in data["ipRanges"]
    assert "microsoft.com" not in data["urls"]
