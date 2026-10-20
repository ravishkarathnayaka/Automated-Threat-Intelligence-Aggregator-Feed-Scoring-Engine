"""Unit tests for TLD reputation processor."""

from cti_core.processors.tld_reputation import TLDReputationProcessor


def test_tld_extraction():
    assert TLDReputationProcessor.extract_tld("malicious.phish.top") == "top"
    assert TLDReputationProcessor.extract_tld("evil.tk.") == "tk"
    assert TLDReputationProcessor.extract_tld("nodot") == ""


def test_suspicious_tld_evaluation():
    penalty, risk = TLDReputationProcessor.evaluate("payload-drop.tk")
    assert penalty == 30.0
    assert risk == "high_risk_tld"

    penalty_xyz, risk_xyz = TLDReputationProcessor.evaluate("bank-login.xyz")
    assert penalty_xyz == 20.0
    assert risk_xyz == "suspicious_tld"


def test_trusted_infrastructure_tld():
    penalty, risk = TLDReputationProcessor.evaluate("cisa.dhs.gov")
    assert penalty == -10.0
    assert risk == "trusted_infrastructure"


def test_standard_tld():
    penalty, risk = TLDReputationProcessor.evaluate("example.com")
    assert penalty == 0.0
    assert risk == "standard_tld"
