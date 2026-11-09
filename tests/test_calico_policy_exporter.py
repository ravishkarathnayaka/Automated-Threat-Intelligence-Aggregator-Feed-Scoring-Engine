"""Unit tests for Project Calico GlobalNetworkPolicy YAML exporter."""

from cti_core.exporters.calico_policy_exporter import CalicoPolicyExporter


def test_calico_policy_export():
    indicators = [
        {"normalized_value": "198.51.100.19", "type": "ipv4", "confidence_score": 88.0, "is_whitelisted": False},
        {"normalized_value": "203.0.113.42", "type": "ipv4", "confidence_score": 81.0, "is_whitelisted": False},
        {"normalized_value": "8.8.8.8", "type": "ipv4", "confidence_score": 99.0, "is_whitelisted": True},
    ]

    out_yaml = CalicoPolicyExporter.export_yaml_manifest(
        indicators,
        policy_name="calico-zero-trust-c2-drop",
        min_score=75.0,
    )

    assert "apiVersion: projectcalico.org/v3" in out_yaml
    assert "kind: GlobalNetworkPolicy" in out_yaml
    assert "name: calico-zero-trust-c2-drop" in out_yaml
    assert "action: Deny" in out_yaml
    assert '- "198.51.100.19/32"' in out_yaml
    assert '- "203.0.113.42/32"' in out_yaml
    assert "8.8.8.8" not in out_yaml
