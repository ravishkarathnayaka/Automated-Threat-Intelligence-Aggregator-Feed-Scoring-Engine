"""Unit tests for MAC/EUI-64 address normalizer."""

from cti_core.processors.mac_address_normalizer import MACNormalizer


def test_mac_formats():
    # Colon separated
    c1, t1 = MACNormalizer.normalize("00:1A:2B:3C:4D:5E")
    assert c1 == "00:1a:2b:3c:4d:5e"
    assert t1 == "eui48"

    # Hyphen separated
    c2, t2 = MACNormalizer.normalize("00-1A-2B-3C-4D-5E")
    assert c2 == "00:1a:2b:3c:4d:5e"

    # Cisco dot notation
    c3, t3 = MACNormalizer.normalize("001a.2b3c.4d5e")
    assert c3 == "00:1a:2b:3c:4d:5e"


def test_eui64_format():
    c, t = MACNormalizer.normalize("00:1A:2B:FF:FE:3C:4D:5E")
    assert c == "00:1a:2b:ff:fe:3c:4d:5e"
    assert t == "eui64"


def test_invalid_mac():
    assert MACNormalizer.normalize("invalid-mac") is None
