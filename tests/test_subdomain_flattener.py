"""Unit tests for subdomain flattener and DDNS detector."""

from cti_core.processors.subdomain_flattener import SubdomainFlattener


def test_ddns_detection():
    res = SubdomainFlattener.analyze_domain("evil-c2-beacon.duckdns.org")
    assert res["is_ddns"] is True
    assert res["ddns_provider"] == "duckdns.org"
    assert res["subdomain"] == "evil-c2-beacon"
    assert res["apex_domain"] == "duckdns.org"


def test_standard_domain():
    res = SubdomainFlattener.analyze_domain("login.stage.bank-phish.com")
    assert res["is_ddns"] is False
    assert res["apex_domain"] == "bank-phish.com"
    assert res["subdomain"] == "login.stage"


def test_single_label():
    res = SubdomainFlattener.analyze_domain("localhost")
    assert res["is_ddns"] is False
    assert res["apex_domain"] == "localhost"
