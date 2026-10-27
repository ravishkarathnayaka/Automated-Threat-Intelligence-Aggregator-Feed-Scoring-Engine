"""Unit tests for JA4X certificate fingerprint analyzer."""

from cti_core.processors.ja4x_certificate_processor import JA4XCertificateProcessor


def test_ja4x_validation_and_classification():
    # Valid Cobalt Strike default cert
    penalty, desc = JA4XCertificateProcessor.evaluate("185a973d0a21_b7538a735178_8daaf6152771")
    assert penalty == 35.0
    assert "Cobalt Strike" in desc

    # Valid Metasploit snakeoil cert
    penalty, desc = JA4XCertificateProcessor.evaluate("c9e6e409b62a_000000000000_123456789abc")
    assert penalty == 30.0
    assert "Metasploit" in desc

    # Benign / Unclassified
    penalty, desc = JA4XCertificateProcessor.evaluate("000000000000_000000000000_000000000000")
    assert penalty == 0.0
    assert desc == "unclassified_ja4x"

    # Missing / Invalid
    assert JA4XCertificateProcessor.evaluate(None)[1] == "missing_ja4x"
    assert JA4XCertificateProcessor.evaluate("too_short")[1] == "invalid_ja4x_format"
