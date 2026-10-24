"""Unit tests for Cisco Firepower FMC exporter."""

import json
from cti_core.exporters.cisco_firepower_exporter import CiscoFirepowerExporter


def test_cisco_firepower_export():
    indicators = [
        {"normalized_value": "198.51.100.14", "type": "ipv4", "confidence_score": 88.0, "is_whitelisted": False},
        {"normalized_value": "c2-bad-domain.net", "type": "domain", "confidence_score": 92.0, "is_whitelisted": False},
        {"normalized_value": "1.1.1.1", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": True},
        {"normalized_value": "192.0.2.1", "type": "ipv4", "confidence_score": 40.0, "is_whitelisted": False},
    ]

    out_json = CiscoFirepowerExporter.export_fmc_objects(indicators, min_score=75.0)
    data = json.loads(out_json)

    assert data["generator"] == "SENTINEL-CTI-Engine"
    assert data["totalCount"] == 2
    assert len(data["networkObjects"]) == 2

    host_obj = data["networkObjects"][0]
    assert host_obj["name"] == "SENTINEL_HOST_198_51_100_14"
    assert host_obj["type"] == "Host"
    assert host_obj["value"] == "198.51.100.14"

    fqdn_obj = data["networkObjects"][1]
    assert fqdn_obj["name"] == "SENTINEL_DNS_c2-bad-domain_net"
    assert fqdn_obj["type"] == "FQDN"
    assert fqdn_obj["value"] == "c2-bad-domain.net"
