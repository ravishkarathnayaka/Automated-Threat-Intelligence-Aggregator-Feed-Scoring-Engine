"""Unit tests for SonicWall SonicOS exporter."""

from cti_core.exporters.sonicwall_exporter import SonicWallExporter


def test_sonicwall_export():
    indicators = [
        {"normalized_value": "198.51.100.99", "type": "ipv4", "confidence_score": 82.0, "is_whitelisted": False},
        {"normalized_value": "trojan-download.biz", "type": "domain", "confidence_score": 87.0, "is_whitelisted": False},
        {"normalized_value": "127.0.0.1", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": True},
    ]

    out_script = SonicWallExporter.export_cli_commands(
        indicators,
        group_name="CTI_WAN_DROP",
        min_score=75.0,
    )

    assert "address-object ipv4 THREAT_IP_198_51_100_99 host 198.51.100.99 zone WAN" in out_script
    assert "address-object fqdn THREAT_FQDN_trojan-download_biz domain trojan-download.biz zone WAN" in out_script
    assert "address-group ipv4 CTI_WAN_DROP" in out_script
    assert "commit" in out_script
    assert "127.0.0.1" not in out_script
