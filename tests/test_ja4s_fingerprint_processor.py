"""Unit tests for JA4S TLS server response fingerprint analyzer."""

from cti_core.processors.ja4s_fingerprint_processor import JA4SFingerprintProcessor


def test_ja4s_validation_and_classification():
    # Valid Cobalt Strike
    penalty, desc = JA4SFingerprintProcessor.evaluate("t1302h2_1301_a56c5b992b27")
    assert penalty == 30.0
    assert "Cobalt Strike" in desc

    # Valid Sliver C2
    penalty, desc = JA4SFingerprintProcessor.evaluate("t1304h2_1302_49479b76c8c4")
    assert penalty == 35.0
    assert "Sliver C2" in desc

    # Benign / Unclassified
    penalty, desc = JA4SFingerprintProcessor.evaluate("t1302h2_1301_000000000000")
    assert penalty == 0.0
    assert desc == "unclassified_ja4s"

    # Invalid / Missing
    assert JA4SFingerprintProcessor.evaluate(None)[1] == "missing_ja4s"
    assert JA4SFingerprintProcessor.evaluate("invalid_ja4s")[1] == "invalid_ja4s_format"
