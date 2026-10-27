"""Unit tests for Cloudflare Zero Trust Gateway exporter."""

import json
from cti_core.exporters.cloudflare_zerotrust_exporter import CloudflareZeroTrustExporter


def test_cloudflare_zerotrust_export():
    indicators = [
        {"normalized_value": "198.51.100.33", "type": "ipv4", "confidence_score": 86.0, "is_whitelisted": False},
        {"normalized_value": "phish-stealer.top", "type": "domain", "confidence_score": 90.0, "is_whitelisted": False},
        {"normalized_value": "cloudflare.com", "type": "domain", "confidence_score": 95.0, "is_whitelisted": True},
    ]

    out_json = CloudflareZeroTrustExporter.export_list_items(
        indicators,
        list_name="Edge-Threat-List",
        min_score=75.0,
    )
    data = json.loads(out_json)

    assert data["name"] == "Edge-Threat-List"
    assert len(data["items"]) == 2
    assert data["items"][0]["value"] == "198.51.100.33"
    assert data["items"][1]["value"] == "phish-stealer.top"
    assert "cloudflare.com" not in out_json
