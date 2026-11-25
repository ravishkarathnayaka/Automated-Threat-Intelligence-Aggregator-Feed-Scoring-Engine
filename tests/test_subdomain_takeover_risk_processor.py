"""Unit tests for Subdomain Takeover risk processor."""

from cti_core.processors.subdomain_takeover_risk_processor import SubdomainTakeoverProcessor


def test_subdomain_takeover_evaluation():
    # Verified dangling S3 bucket with 404 error
    is_vuln, penalty, desc = SubdomainTakeoverProcessor.evaluate(
        cname_target="my-bucket.s3.amazonaws.com",
        http_response_body="<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>",
    )
    assert is_vuln is True
    assert penalty == 35.0
    assert "verified_subdomain_takeover" in desc

    # Potential takeover pointing to GitHub Pages without response verification
    is_vuln2, penalty2, desc2 = SubdomainTakeoverProcessor.evaluate(
        cname_target="my-project.github.io",
    )
    assert is_vuln2 is True
    assert penalty2 == 20.0

    # Non-vulnerable CNAME
    is_vuln3, penalty3, _ = SubdomainTakeoverProcessor.evaluate("lb.internal.corp")
    assert is_vuln3 is False
    assert penalty3 == 0.0
