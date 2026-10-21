"""Unit tests for malicious User-Agent validator."""

from cti_core.processors.user_agent_parser import UserAgentValidator


def test_offensive_scanners():
    is_mal, score, desc = UserAgentValidator.evaluate("sqlmap/1.6.11#stable (https://sqlmap.org)")
    assert is_mal is True
    assert score == 95.0
    assert "SQL Injection" in desc

    is_mal_nik, score_nik, desc_nik = UserAgentValidator.evaluate("Mozilla/5.00 (Nikto/2.1.6)")
    assert is_mal_nik is True
    assert score_nik == 90.0


def test_c2_framework_user_agents():
    is_mal, score, desc = UserAgentValidator.evaluate("Havoc-Client/0.5")
    assert is_mal is True
    assert score == 98.0


def test_benign_user_agent():
    is_mal, score, desc = UserAgentValidator.evaluate(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    assert is_mal is False
    assert score == 0.0
