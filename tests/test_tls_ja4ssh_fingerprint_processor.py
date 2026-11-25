"""Unit tests for Fox-IT JA4SSH fingerprint analyzer."""

from cti_core.processors.tls_ja4ssh_fingerprint_processor import JA4SSHFingerprintProcessor


def test_ja4ssh_evaluation():
    # Hydra signature
    assert JA4SSHFingerprintProcessor.is_valid_ja4ssh("c_1_0_0_0") is True
    penalty, desc = JA4SSHFingerprintProcessor.evaluate("c_1_0_0_0")
    assert penalty == 35.0
    assert "Hydra" in desc

    # Single-attempt probe heuristic
    penalty2, desc2 = JA4SSHFingerprintProcessor.evaluate("c_2_1_5_2")
    assert penalty2 == 25.0
    assert "automated" in desc2

    # Standard interactive session
    penalty3, desc3 = JA4SSHFingerprintProcessor.evaluate("c_85_92_45_20")
    assert penalty3 == 0.0
    assert desc3 == "standard_interactive_ssh_session"

    # Invalid
    assert JA4SSHFingerprintProcessor.evaluate("bad_fp")[1] == "invalid_ja4ssh_format"
