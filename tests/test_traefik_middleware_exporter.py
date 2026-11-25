"""Unit tests for Traefik IngressRoute Middleware exporter."""

from cti_core.exporters.traefik_middleware_exporter import TraefikMiddlewareExporter


def test_traefik_middleware_export():
    indicators = [
        {"normalized_value": "198.51.100.22", "type": "ipv4", "confidence_score": 88.0, "is_whitelisted": False},
        {"normalized_value": "203.0.113.67", "type": "ipv4", "confidence_score": 79.0, "is_whitelisted": False},
        {"normalized_value": "8.8.8.8", "type": "ipv4", "confidence_score": 95.0, "is_whitelisted": True},
    ]

    out_yaml = TraefikMiddlewareExporter.export_yaml_manifest(
        indicators,
        namespace="traefik",
        middleware_name="sentinel-block-c2",
        min_score=75.0,
    )

    assert "kind: Middleware" in out_yaml
    assert "namespace: traefik" in out_yaml
    assert "name: sentinel-block-c2" in out_yaml
    assert '- "198.51.100.22/32"' in out_yaml
    assert '- "203.0.113.67/32"' in out_yaml
    assert "8.8.8.8" not in out_yaml
