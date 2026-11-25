"""Unit tests for TLS SNI domain fronting detector."""

from cti_core.processors.tls_sni_proxy_domain_fronting_detector import DomainFrontingDetector


def test_domain_fronting_detection():
    # Legitimate matching traffic
    is_front, penalty, desc = DomainFrontingDetector.evaluate("api.example.com", "api.example.com")
    assert is_front is False
    assert penalty == 0.0

    # CDN fronting: legitimate CloudFront SNI hiding malicious C2 host
    is_front2, penalty2, desc2 = DomainFrontingDetector.evaluate("d111111abcdef8.cloudfront.net", "c2-hidden-apt.top")
    assert is_front2 is True
    assert penalty2 == 35.0
    assert "domain_fronting" in desc2

    # Generic SNI vs Host mismatch
    is_front3, penalty3, _ = DomainFrontingDetector.evaluate("legit.org", "evil.org")
    assert is_front3 is True
    assert penalty3 == 25.0
