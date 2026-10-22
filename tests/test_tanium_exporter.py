"""Unit tests for Tanium Threat Response IOC package exporter."""

import json
from cti_core.exporters.tanium_exporter import TaniumExporter


def test_tanium_package_export():
    indicators = [
        {"normalized_value": "198.51.100.77", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": False},
        {"normalized_value": "malicious-c2.com", "type": "domain", "confidence_score": 75.0, "is_whitelisted": False},
        {"normalized_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "type": "sha256", "confidence_score": 88.0, "is_whitelisted": False},
        {"normalized_value": "8.8.8.8", "type": "ipv4", "confidence_score": 99.0, "is_whitelisted": True},
        {"normalized_value": "low.xyz", "type": "domain", "confidence_score": 40.0, "is_whitelisted": False},
    ]

    pkg = TaniumExporter.export_package(indicators, min_score=70.0)
    assert pkg["name"] == "Sentinel-Threat-Response-Package"
    assert len(pkg["threat_intel_iocs"]) == 3
    types = [i["type"] for i in pkg["threat_intel_iocs"]]
    assert "IPAddress" in types
    assert "DomainName" in types
    assert "Sha256" in types

    json_str = TaniumExporter.export_json(indicators, min_score=70.0)
    parsed = json.loads(json_str)
    assert parsed["schema_version"] == "2.0"
