"""Unit tests for Weibull hazard rate model."""

from cti_core.scoring.weibull_reliability_model import WeibullReliabilityModel


def test_weibull_survival_at_scale():
    # When t = scale, R(t) = exp(-1) ~ 0.3678
    p = WeibullReliabilityModel.survival_probability(age_days=8.0, ioc_type="ipv4")
    assert abs(p - 0.3678) < 0.05

    score = WeibullReliabilityModel.calculate_weibull_decayed_score(100.0, age_days=8.0, ioc_type="ipv4")
    assert 30.0 < score < 42.0


def test_weibull_zero_age():
    p = WeibullReliabilityModel.survival_probability(age_days=0.0)
    assert p == 1.0


def test_weibull_phishing_url_fast_decay():
    # URLs drop drastically after 3 days
    p_url = WeibullReliabilityModel.survival_probability(age_days=3.0, ioc_type="url")
    p_hash = WeibullReliabilityModel.survival_probability(age_days=3.0, ioc_type="sha256")
    assert p_url < p_hash
