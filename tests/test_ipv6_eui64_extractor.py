"""Unit tests for IPv6 modified EUI-64 MAC address extractor."""

from cti_core.processors.ipv6_eui64_extractor import IPv6EUI64Extractor


def test_ipv6_eui64_extraction():
    # Example SLAAC address: 2001:db8:1::021a:2bff:fe3c:4d5e
    # MAC was 00:1a:2b:3c:4d:5e -> byte 0 (00 ^ 02 = 02) -> 02:1a:2b:ff:fe:3c:4d:5e
    ipv6 = "2001:db8:1::021a:2bff:fe3c:4d5e"
    has_eui, mac, oui = IPv6EUI64Extractor.extract_mac(ipv6)

    assert has_eui is True
    assert mac == "00:1A:2B:3C:4D:5E"
    assert oui == "00:1A:2B"

    # Non-EUI64 address
    non_eui = "2001:db8::1"
    has_eui, mac, oui = IPv6EUI64Extractor.extract_mac(non_eui)
    assert has_eui is False
    assert mac is None
    assert oui is None
