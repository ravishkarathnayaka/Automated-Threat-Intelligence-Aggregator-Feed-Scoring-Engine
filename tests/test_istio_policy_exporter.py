"""Unit tests for Istio AuthorizationPolicy exporter."""

from cti_core.exporters.istio_policy_exporter import IstioPolicyExporter


def test_istio_policy_export():
    indicators = [
        {"normalized_value": "198.51.100.25", "type": "ipv4", "confidence_score": 88.0, "is_whitelisted": False},
        {"normalized_value": "203.0.113.50", "type": "ipv4", "confidence_score": 79.0, "is_whitelisted": False},
        {"normalized_value": "8.8.8.8", "type": "ipv4", "confidence_score": 95.0, "is_whitelisted": True},
        {"normalized_value": "192.0.2.1", "type": "ipv4", "confidence_score": 40.0, "is_whitelisted": False},
    ]

    out_yaml = IstioPolicyExporter.export_yaml_manifest(
        indicators,
        namespace="istio-ingress",
        policy_name="block-c2-perimeter",
        min_score=75.0,
    )

    assert "kind: AuthorizationPolicy" in out_yaml
    assert "namespace: istio-ingress" in out_yaml
    assert "name: block-c2-perimeter" in out_yaml
    assert "action: DENY" in out_yaml
    assert '- "198.51.100.25/32"' in out_yaml
    assert '- "203.0.113.50/32"' in out_yaml
    assert "8.8.8.8" not in out_yaml
    assert "192.0.2.1" not in out_yaml
