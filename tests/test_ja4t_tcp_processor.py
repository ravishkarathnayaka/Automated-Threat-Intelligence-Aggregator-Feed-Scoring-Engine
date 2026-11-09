"""Unit tests for Fox-IT JA4T TCP stack fingerprint analyzer."""

from cti_core.processors.ja4t_tcp_processor import JA4TTCPProcessor


def test_ja4t_validation_and_classification():
    # Masscan signature
    assert JA4TTCPProcessor.is_valid_ja4t("1024_2_1460_0") is True
    penalty, desc = JA4TTCPProcessor.evaluate("1024_2_1460_0")
    assert penalty == 35.0
    assert "Masscan" in desc

    # Custom raw socket SYN scanner
    penalty2, desc2 = JA4TTCPProcessor.evaluate("2048_2_1400_0")
    assert penalty2 == 25.0
    assert "raw_socket" in desc2

    # Standard OS TCP stack
    penalty3, desc3 = JA4TTCPProcessor.evaluate("64240_2-1-3-1-1-4_1460_8")
    assert penalty3 == 0.0
    assert desc3 == "normal_tcp_stack_ja4t"

    # Invalid / Missing
    assert JA4TTCPProcessor.evaluate(None)[1] == "missing_ja4t"
    assert JA4TTCPProcessor.evaluate("bad_tcp")[1] == "invalid_ja4t_format"
