"""Unit tests for domain registrar classifier."""

from cti_core.processors.whois_registrar_classifier import RegistrarClassifier


def test_high_risk_registrar():
    penalty, verdict = RegistrarClassifier.evaluate("NameSilo, LLC")
    assert penalty == 15.0
    assert "high_risk_registrar" in verdict


def test_enterprise_trusted_registrar():
    penalty, verdict = RegistrarClassifier.evaluate("MarkMonitor Inc.")
    assert penalty == -10.0
    assert "enterprise_trusted_registrar" in verdict


def test_unknown_and_standard_registrar():
    penalty, verdict = RegistrarClassifier.evaluate("")
    assert penalty == 0.0
    assert verdict == "unknown_registrar"

    penalty, verdict = RegistrarClassifier.evaluate("GoDaddy.com, LLC")
    assert penalty == 0.0
    assert verdict == "standard_commercial_registrar"
