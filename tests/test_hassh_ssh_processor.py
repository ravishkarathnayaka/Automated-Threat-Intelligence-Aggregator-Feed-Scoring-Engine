"""Unit tests for HASSH SSH processor."""

from cti_core.processors.hassh_ssh_processor import HasshSSHProcessor


def test_hassh_validation_and_classification():
    # Valid Hydra brute-forcer
    penalty, desc = HasshSSHProcessor.evaluate("b123456789abcdef0123456789abcdef")
    assert penalty == 25.0
    assert "Hydra" in desc

    # Valid Mirai botnet
    penalty, desc = HasshSSHProcessor.evaluate("d5555555555555555555555555555555")
    assert penalty == 35.0
    assert "Mirai" in desc

    # Benign / Unclassified
    penalty, desc = HasshSSHProcessor.evaluate("ffffffffffffffffffffffffffffffff")
    assert penalty == 0.0
    assert desc == "unclassified_hassh"

    # Missing / Invalid
    assert HasshSSHProcessor.evaluate(None)[1] == "missing_hassh"
    assert HasshSSHProcessor.evaluate("short-hash")[1] == "invalid_hassh_format"
