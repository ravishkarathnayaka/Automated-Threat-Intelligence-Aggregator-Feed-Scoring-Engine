"""Unit tests for DNS over HTTPS detector."""

from cti_core.processors.doh_anomaly_detector import DNSOverHTTPSDetector


def test_doh_domain_detection():
    is_doh, penalty, desc = DNSOverHTTPSDetector.evaluate("cloudflare-dns.com", "domain")
    assert is_doh is True
    assert penalty == 15.0
    assert "Cloudflare" in desc

    is_doh, penalty, desc = DNSOverHTTPSDetector.evaluate("custom.dns.nextdns.io", "domain")
    assert is_doh is True
    assert penalty == 20.0
    assert "NextDNS" in desc

    is_doh, penalty, desc = DNSOverHTTPSDetector.evaluate("legitimate-service.org", "domain")
    assert is_doh is False
    assert penalty == 0.0


def test_doh_ip_detection():
    is_doh, penalty, desc = DNSOverHTTPSDetector.evaluate("1.1.1.1", "ipv4")
    assert is_doh is True
    assert penalty == 15.0

    is_doh, penalty, desc = DNSOverHTTPSDetector.evaluate("198.51.100.2", "ipv4")
    assert is_doh is False
    assert penalty == 0.0
