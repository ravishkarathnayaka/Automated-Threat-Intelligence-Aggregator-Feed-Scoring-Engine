"""Unit tests for port service mapper."""

from cti_core.processors.port_service_mapper import PortServiceMapper


def test_high_risk_backdoor_ports():
    is_ano, desc, pen = PortServiceMapper.evaluate_port(4444)
    assert is_ano is True
    assert "Metasploit" in desc
    assert pen == 25.0

    is_ano_bot, desc_bot, pen_bot = PortServiceMapper.evaluate_port(6667)
    assert is_ano_bot is True
    assert "IRC botnet" in desc_bot


def test_standard_ports():
    is_ano, desc, pen = PortServiceMapper.evaluate_port(443)
    assert is_ano is False
    assert desc == "HTTPS"
    assert pen == 0.0


def test_invalid_port():
    is_ano, desc, pen = PortServiceMapper.evaluate_port(99999)
    assert is_ano is False
    assert desc == "invalid_or_missing_port"
