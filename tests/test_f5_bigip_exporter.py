"""Unit tests for F5 BIG-IP TMSH exporter."""

from cti_core.exporters.f5_bigip_exporter import F5BigIPExporter


def test_f5_bigip_export():
    indicators = [
        {"normalized_value": "198.51.100.77", "type": "ipv4", "confidence_score": 91.0, "is_whitelisted": False},
        {"normalized_value": "192.168.0.1", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": True},
    ]

    out_tmsh = F5BigIPExporter.export_tmsh_commands(
        indicators,
        data_group_name="botnet_c2_group",
        min_score=75.0,
    )

    assert "modify ltm data-group internal botnet_c2_group type ip records replace-all-with {" in out_tmsh
    assert '198.51.100.77/32 { data "score=91.0" }' in out_tmsh
    assert "192.168.0.1" not in out_tmsh
