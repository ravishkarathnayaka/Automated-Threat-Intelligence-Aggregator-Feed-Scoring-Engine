"""Unit tests for User-Agent anomaly detector."""

from cti_core.processors.user_agent_anomaly_detector import UserAgentAnomalyDetector


def test_standard_browser_agent():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    penalty, verdict = UserAgentAnomalyDetector.evaluate(ua)
    assert penalty == 0.0
    assert verdict == "standard_browser_signature"


def test_short_and_empty_agents():
    penalty, verdict = UserAgentAnomalyDetector.evaluate("")
    assert penalty == 25.0

    penalty, verdict = UserAgentAnomalyDetector.evaluate("curl/7.68")
    assert penalty == 20.0
    assert verdict == "atypically_short_user_agent"


def test_random_high_entropy_agent():
    # Long random hex string as user agent
    ua = "x9kjq182390zxclvkajsdf09123849182349018234"
    penalty, verdict = UserAgentAnomalyDetector.evaluate(ua)
    assert penalty >= 25.0
    assert "high_entropy" in verdict or "non_standard" in verdict
