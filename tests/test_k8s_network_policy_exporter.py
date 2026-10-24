"""Unit tests for Kubernetes NetworkPolicy exporter."""

from cti_core.exporters.k8s_network_policy_exporter import K8sNetworkPolicyExporter


def test_k8s_network_policy_export():
    indicators = [
        {"normalized_value": "198.51.100.10", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "203.0.113.0/24", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": False},
        {"normalized_value": "10.0.0.1", "type": "ipv4", "confidence_score": 95.0, "is_whitelisted": True},
    ]

    out_yaml = K8sNetworkPolicyExporter.export_yaml_manifest(
        indicators,
        namespace="prod-workloads",
        policy_name="quarantine-c2-egress",
        min_score=75.0,
    )

    assert "kind: NetworkPolicy" in out_yaml
    assert "namespace: prod-workloads" in out_yaml
    assert "name: quarantine-c2-egress" in out_yaml
    assert "        - 198.51.100.10/32" in out_yaml
    assert "        - 203.0.113.0/24" in out_yaml
    assert "10.0.0.1" not in out_yaml
