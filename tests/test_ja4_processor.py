"""Unit tests for Fox-IT JA4 TLS client fingerprint processor."""

from cti_core.processors.ja4_fingerprint_processor import JA4FingerprintProcessor


def test_valid_and_malicious_ja4():
    ja4 = "t13d1516h2_8daaf6152771_b7538a735178"
    assert JA4FingerprintProcessor.is_valid_ja4(ja4) is True

    penalty, verdict = JA4FingerprintProcessor.evaluate(ja4)
    assert penalty == 30.0
    assert "Cobalt Strike" in verdict


def test_unclassified_ja4():
    ja4 = "t13d1204h2_000000000000_111111111111"
    assert JA4FingerprintProcessor.is_valid_ja4(ja4) is True
    penalty, verdict = JA4FingerprintProcessor.evaluate(ja4)
    assert penalty == 0.0
    assert verdict == "unclassified_ja4"


def test_invalid_ja4():
    assert JA4FingerprintProcessor.is_valid_ja4("not_a_ja4") is False
    penalty, verdict = JA4FingerprintProcessor.evaluate("not_a_ja4")
    assert penalty == 0.0
    assert verdict == "invalid_ja4_format"
