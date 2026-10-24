"""Unit tests for Arista EOS exporter."""

from cti_core.exporters.arista_eos_exporter import AristaEOSExporter


def test_arista_eos_export():
    indicators = [
        {"normalized_value": "198.51.100.22", "type": "ipv4", "confidence_score": 86.0, "is_whitelisted": False},
        {"normalized_value": "203.0.113.88", "type": "ipv4", "confidence_score": 79.0, "is_whitelisted": False},
        {"normalized_value": "8.8.4.4", "type": "ipv4", "confidence_score": 95.0, "is_whitelisted": True},
    ]

    out_acl = AristaEOSExporter.export_acl_config(
        indicators,
        acl_name="EDGE_CTI_INBOUND",
        min_score=75.0,
    )

    assert "ip access-list EDGE_CTI_INBOUND" in out_acl
    assert " 10 deny ip any 198.51.100.22/32 log" in out_acl
    assert " 20 deny ip any 203.0.113.88/32 log" in out_acl
    assert " 30 permit ip any any" in out_acl
    assert "8.8.4.4" not in out_acl
