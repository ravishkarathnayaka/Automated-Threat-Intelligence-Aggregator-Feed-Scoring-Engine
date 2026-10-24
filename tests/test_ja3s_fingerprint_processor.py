"""Unit tests for JA3S TLS server fingerprint processor."""

from cti_core.processors.ja3s_fingerprint_processor import JA3SFingerprintProcessor


def test_ja3s_validation_and_classification():
    # Valid Cobalt Strike
    penalty, desc = JA3SFingerprintProcessor.evaluate("fd4bc6036cb6b517d7455d320d57aec3")
    assert penalty == 30.0
    assert "Cobalt Strike" in desc

    # Valid Metasploit
    penalty, desc = JA3SFingerprintProcessor.evaluate("e35df3e00ca4ef31d42b34bebaa2f86e")
    assert penalty == 35.0
    assert "Metasploit" in desc

    # Benign / Unclassified
    penalty, desc = JA3SFingerprintProcessor.evaluate("11111111111111111111111111111111")
    assert penalty == 0.0
    assert desc == "unclassified_ja3s"

    # Invalid / Missing
    assert JA3SFingerprintProcessor.evaluate("")[1] == "missing_ja3s"
    assert JA3SFingerprintProcessor.evaluate("not-an-md5")[1] == "invalid_ja3s_format"
