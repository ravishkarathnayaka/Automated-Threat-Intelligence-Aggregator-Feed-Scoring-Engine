"""Unit tests for Juniper Junos SRX exporter."""

from cti_core.exporters.juniper_srx_exporter import JuniperSRXExporter


def test_juniper_srx_export():
    indicators = [
        {"normalized_value": "203.0.113.5", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "phish-portal.org", "type": "domain", "confidence_score": 80.0, "is_whitelisted": False},
        {"normalized_value": "8.8.8.8", "type": "ipv4", "confidence_score": 90.0, "is_whitelisted": True},
    ]

    out_script = JuniperSRXExporter.export_set_commands(
        indicators,
        zone_name="dmz",
        address_set_name="BAD_IPS",
        min_score=75.0,
    )

    assert "set security zones security-zone dmz address-book address-set BAD_IPS" in out_script
    assert "set security zones security-zone dmz address-book address THREAT_203_0_113_5 203.0.113.5/32" in out_script
    assert "set security zones security-zone dmz address-book address DNS_phish-portal_org dns-name phish-portal.org" in out_script
    assert "8.8.8.8" not in out_script
