"""Unit tests for Netskope CASB & SWG URL list exporter."""

import json
from cti_core.exporters.netskope_casb_exporter import NetskopeCASBExporter


def test_netskope_casb_export():
    indicators = [
        {"normalized_value": "c2-panel.evil.top", "type": "domain", "confidence_score": 91.0, "is_whitelisted": False},
        {"normalized_value": "198.51.100.44", "type": "ipv4", "confidence_score": 84.0, "is_whitelisted": False},
        {"normalized_value": "google.com", "type": "domain", "confidence_score": 99.0, "is_whitelisted": True},
        {"normalized_value": "low-risk.org", "type": "domain", "confidence_score": 45.0, "is_whitelisted": False},
    ]

    out_json = NetskopeCASBExporter.export_url_list_json(
        indicators,
        list_name="Sentinel-Netskope-SWG",
        min_score=75.0,
    )
    data = json.loads(out_json)

    assert data["name"] == "Sentinel-Netskope-SWG"
    assert data["data"]["type"] == "exact"
    assert "c2-panel.evil.top" in data["data"]["urls"]
    assert "198.51.100.44" in data["data"]["urls"]
    assert "google.com" not in data["data"]["urls"]
    assert "low-risk.org" not in data["data"]["urls"]
