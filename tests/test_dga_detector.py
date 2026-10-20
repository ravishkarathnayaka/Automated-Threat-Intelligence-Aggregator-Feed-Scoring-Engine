"""Unit tests for Shannon entropy DGA detector."""

from cti_core.processors.dga_detector import DGADetector


def test_benign_domains_not_dga():
    # Legitimate English/readable domains
    is_dga, entropy, reason = DGADetector.evaluate("threat-intelligence-engine.com")
    assert is_dga is False

    is_dga2, entropy2, reason2 = DGADetector.evaluate("google.com")
    assert is_dga2 is False
    assert reason2 == "label_too_short"


def test_dga_random_strings():
    # Algorithmic pseudorandom DGA strings
    dga_domain = "xzkqj918abcfmpqtw.net"
    is_dga, entropy, reason = DGADetector.evaluate(dga_domain)
    assert is_dga is True
    assert entropy > 3.5
    assert "DGA" in reason


def test_shannon_entropy_calculation():
    # Monotonous string has 0 entropy
    assert DGADetector.calculate_entropy("aaaaaaa") == 0.0
    # Higher diversity has higher entropy
    assert DGADetector.calculate_entropy("abcdefghijk") > 3.0
