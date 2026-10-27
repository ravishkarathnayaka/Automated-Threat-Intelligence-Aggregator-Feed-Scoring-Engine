"""Unit tests for Cilium eBPF NetworkPolicy exporter."""

from cti_core.exporters.cilium_policy_exporter import CiliumPolicyExporter


def test_cilium_policy_export():
    indicators = [
        {"normalized_value": "198.51.100.99", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "c2-rat-payload.biz", "type": "domain", "confidence_score": 90.0, "is_whitelisted": False},
        {"normalized_value": "127.0.0.1", "type": "ipv4", "confidence_score": 95.0, "is_whitelisted": True},
    ]

    out_yaml = CiliumPolicyExporter.export_yaml_manifest(
        indicators,
        namespace="prod-services",
        policy_name="block-adversary-nodes",
        min_score=75.0,
    )

    assert "kind: CiliumNetworkPolicy" in out_yaml
    assert "namespace: prod-services" in out_yaml
    assert "name: block-adversary-nodes" in out_yaml
    assert "egressDeny:" in out_yaml
    assert '- cidr: "198.51.100.99/32"' in out_yaml
    assert '- matchName: "c2-rat-payload.biz"' in out_yaml
    assert "127.0.0.1" not in out_yaml
