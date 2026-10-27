"""Unit tests for Envoy Proxy RBAC network filter exporter."""

import json
from cti_core.exporters.envoy_proxy_exporter import EnvoyProxyExporter


def test_envoy_proxy_export():
    indicators = [
        {"normalized_value": "198.51.100.12", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "2001:db8::dead:beef", "type": "ipv6", "confidence_score": 90.0, "is_whitelisted": False},
        {"normalized_value": "10.0.0.1", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": True},
    ]

    out_json = EnvoyProxyExporter.export_rbac_filter(indicators, min_score=75.0)
    data = json.loads(out_json)

    assert data["name"] == "envoy.filters.network.rbac"
    rules = data["typed_config"]["rules"]
    assert rules["action"] == "DENY"
    principals = rules["policies"]["sentinel_threat_policy"]["principals"]
    assert len(principals) == 2
    assert principals[0]["direct_remote_ip"]["address_prefix"] == "198.51.100.12"
    assert principals[0]["direct_remote_ip"]["prefix_len"] == 32
    assert principals[1]["direct_remote_ip"]["address_prefix"] == "2001:db8::dead:beef"
    assert principals[1]["direct_remote_ip"]["prefix_len"] == 128
