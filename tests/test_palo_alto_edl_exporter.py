"""Unit tests for Palo Alto PAN-OS External Dynamic List (EDL) exporter."""

from cti_core.exporters.palo_alto_edl_exporter import PaloAltoEDLExporter


def test_palo_alto_ip_and_domain_edl():
    indicators = [
        {"normalized_value": "198.51.100.88", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "c2-gate.net", "type": "domain", "confidence_score": 90.0, "is_whitelisted": False},
        {"normalized_value": "10.0.0.1", "type": "ipv4", "confidence_score": 95.0, "is_whitelisted": True},
        {"normalized_value": "203.0.113.1", "type": "ipv4", "confidence_score": 45.0, "is_whitelisted": False},
    ]

    ip_edl = PaloAltoEDLExporter.export_ip_edl(indicators, min_score=75.0)
    assert "198.51.100.88" in ip_edl
    assert "10.0.0.1" not in ip_edl
    assert "203.0.113.1" not in ip_edl

    dom_edl = PaloAltoEDLExporter.export_domain_edl(indicators, min_score=75.0)
    assert "c2-gate.net" in dom_edl
    assert "198.51.100.88" not in dom_edl
