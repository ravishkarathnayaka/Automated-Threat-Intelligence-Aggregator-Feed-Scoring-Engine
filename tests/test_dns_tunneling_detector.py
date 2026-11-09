"""Unit tests for DNS tunneling exfiltration detector."""

from cti_core.processors.dns_tunneling_detector import DNSTunnelingDetector


def test_dns_tunneling_detection():
    # High-entropy long Base32/Hex exfiltration query (dnscat2 / iodine style)
    tunnel_fqdn = "4a6f686e446f6553656372657450617373776f726431323334.9f8e7d6c5b4a.c2-tunnel.evil.com"
    is_tun, penalty, desc = DNSTunnelingDetector.evaluate_query(tunnel_fqdn)
    assert is_tun is True
    assert penalty == 35.0
    assert "exfiltration" in desc

    # Medium encoded C2 beacon subdomain
    beacon_fqdn = "a8f9c2d1e4b70392817465928374ab12.stage.evil.org"
    is_tun2, penalty2, desc2 = DNSTunnelingDetector.evaluate_query(beacon_fqdn)
    assert is_tun2 is True
    assert penalty2 >= 25.0

    # Normal corporate subdomain
    benign_fqdn = "api.staging.payments.example.com"
    is_tun3, penalty3, desc3 = DNSTunnelingDetector.evaluate_query(benign_fqdn)
    assert is_tun3 is False
    assert penalty3 == 0.0
