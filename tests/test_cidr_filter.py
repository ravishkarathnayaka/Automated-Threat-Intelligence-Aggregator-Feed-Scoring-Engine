"""Unit tests verifying CIDR subnet containment and Bogon IP detection."""

from cti_core.processors.cidr_filter import CIDRFilter


def test_bogon_detection_ipv4():
    """Verify standard IPv4 bogon addresses are correctly identified."""
    # CGNAT range
    is_bogon, reason = CIDRFilter.is_bogon("100.64.0.1")
    assert is_bogon is True
    assert "100.64.0.0/10" in str(reason)

    # Documentation TEST-NET-1
    is_bogon, reason = CIDRFilter.is_bogon("192.0.2.45")
    assert is_bogon is True

    # Benchmarking range
    is_bogon, reason = CIDRFilter.is_bogon("198.18.5.10")
    assert is_bogon is True

    # Valid Public IP (not bogon)
    is_bogon, reason = CIDRFilter.is_bogon("185.220.101.5")
    assert is_bogon is False
    assert reason is None


def test_bogon_detection_ipv6():
    """Verify standard IPv6 bogon addresses are identified."""
    # Documentation prefix 2001:db8::
    is_bogon, reason = CIDRFilter.is_bogon("2001:db8::1")
    assert is_bogon is True

    # Unique local fc00::/7
    is_bogon, reason = CIDRFilter.is_bogon("fd00::1234")
    assert is_bogon is True

    # Valid Public IPv6 (Cloudflare)
    is_bogon, reason = CIDRFilter.is_bogon("2606:4700:4700::1111")
    assert is_bogon is False


def test_is_ip_in_subnets():
    """Verify IP containment across a list of CIDR subnets."""
    subnets = ["192.168.1.0/24", "10.50.0.0/16", "172.16.100.0/24"]

    in_sub, match = CIDRFilter.is_ip_in_subnets("192.168.1.150", subnets)
    assert in_sub is True
    assert match == "192.168.1.0/24"

    in_sub, match = CIDRFilter.is_ip_in_subnets("10.50.99.1", subnets)
    assert in_sub is True
    assert match == "10.50.0.0/16"

    in_sub, match = CIDRFilter.is_ip_in_subnets("8.8.8.8", subnets)
    assert in_sub is False
    assert match is None


def test_aggregate_subnets():
    """Verify collapsing contiguous subnets into supernets."""
    raw_subnets = ["10.0.0.0/24", "10.0.1.0/24"]
    collapsed = CIDRFilter.aggregate_subnets(raw_subnets)
    assert collapsed == ["10.0.0.0/23"]
