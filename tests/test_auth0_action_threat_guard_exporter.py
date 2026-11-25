"""Unit tests for Auth0 Post-Login Action code generator."""

from cti_core.exporters.auth0_action_threat_guard_exporter import Auth0ActionThreatGuardExporter


def test_auth0_action_export():
    indicators = [
        {"normalized_value": "198.51.100.55", "type": "ipv4", "confidence_score": 92.0, "is_whitelisted": False},
        {"normalized_value": "203.0.113.99", "type": "ipv4", "confidence_score": 85.0, "is_whitelisted": False},
        {"normalized_value": "8.8.8.8", "type": "ipv4", "confidence_score": 99.0, "is_whitelisted": True},
    ]

    code = Auth0ActionThreatGuardExporter.export_action_javascript(indicators, min_score=75.0)

    assert "exports.onExecutePostLogin" in code
    assert "198.51.100.55" in code
    assert "203.0.113.99" in code
    assert "8.8.8.8" not in code
