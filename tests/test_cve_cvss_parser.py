"""Unit tests for CVSS v3.1 vector parser."""

from cti_core.processors.cve_cvss_parser import CVSSParser


def test_cvss_log4j_critical_parsing():
    # Log4Shell vector: Network, Low complexity, None priv, None UI, High C/I/A
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    parsed = CVSSParser.parse_vector(vec)
    assert parsed is not None
    assert parsed["attack_vector"] == "NETWORK"
    assert parsed["attack_complexity"] == "LOW"
    assert parsed["privileges_required"] == "NONE"
    assert parsed["user_interaction"] == "NONE"
    assert parsed["severity_estimate"] == "CRITICAL"
    assert parsed["is_unauthenticated_rce"] is True


def test_cvss_local_privilege_escalation():
    # Local priv escalation
    vec = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    parsed = CVSSParser.parse_vector(vec)
    assert parsed is not None
    assert parsed["attack_vector"] == "LOCAL"
    assert parsed["is_unauthenticated_rce"] is False


def test_invalid_vector():
    assert CVSSParser.parse_vector("not-a-vector") is None
