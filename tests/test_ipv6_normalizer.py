"""Unit tests verifying IPv6 compression, expansion, and IPv4-mapped translations."""

from cti_core.processors.ipv6_normalizer import IPv6Normalizer


def test_ipv6_compression_and_expansion():
    """Verify RFC 5952 compression and full hextet expansion."""
    raw = "2001:0db8:0000:0000:0000:ff00:0042:8329"
    compressed = IPv6Normalizer.compress_ipv6(raw)
    assert compressed == "2001:db8::ff00:42:8329"

    expanded = IPv6Normalizer.expand_ipv6(compressed)
    assert expanded == "2001:0db8:0000:0000:0000:ff00:0042:8329"


def test_strip_zone_index():
    """Verify link-local zone scope stripping."""
    scoped = "fe80::1ff:fe00:3a60%eth0"
    stripped = IPv6Normalizer.strip_zone_index(scoped)
    assert stripped == "fe80::1ff:fe00:3a60"
    assert IPv6Normalizer.compress_ipv6(scoped) == "fe80::1ff:fe00:3a60"


def test_ipv4_mapped_ipv6():
    """Verify extracting IPv4 from ::ffff:w.x.y.z."""
    mapped = "::ffff:192.0.2.128"
    is_mapped, extracted = IPv6Normalizer.is_ipv4_mapped(mapped)
    assert is_mapped is True
    assert extracted == "192.0.2.128"

    regular = "2001:db8::1"
    is_mapped, extracted = IPv6Normalizer.is_ipv4_mapped(regular)
    assert is_mapped is False
    assert extracted is None
