"""Unit tests for geographic reputation scoring."""

from cti_core.processors.geo_reputation import GeoReputationProcessor


def test_high_risk_countries():
    penalty_kp, risk_kp = GeoReputationProcessor.evaluate_country("KP")
    assert penalty_kp == 30.0
    assert risk_kp == "critical_geopolitical_risk"

    penalty_ru, risk_ru = GeoReputationProcessor.evaluate_country("ru")
    assert penalty_ru == 25.0
    assert risk_ru == "critical_geopolitical_risk"


def test_standard_and_unknown_country():
    penalty_us, risk_us = GeoReputationProcessor.evaluate_country("US")
    assert penalty_us == 0.0
    assert risk_us == "standard_geopolitical_risk"

    penalty_none, risk_none = GeoReputationProcessor.evaluate_country(None)
    assert penalty_none == 0.0
    assert risk_none == "unknown_country"
