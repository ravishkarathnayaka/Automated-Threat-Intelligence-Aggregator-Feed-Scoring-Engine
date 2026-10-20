"""Unit tests for JA3/JA4 TLS fingerprinting."""

from cti_core.processors.tls_fingerprint import TLSFingerprintValidator


def test_ja3_format_and_lookup():
    valid_ja3 = "72a589da586844d7f0818ce684948eea"
    assert TLSFingerprintValidator.identify_type(valid_ja3) == "ja3"

    is_mal, threat = TLSFingerprintValidator.evaluate(valid_ja3)
    assert is_mal is True
    assert "Cobalt Strike" in threat


def test_ja4_format_identification():
    valid_ja4 = "t13d1516h2_8daaf6152771_0190a6125a2e"
    assert TLSFingerprintValidator.identify_type(valid_ja4) == "ja4"


def test_invalid_fingerprint():
    assert TLSFingerprintValidator.identify_type("not-a-hash") is None
