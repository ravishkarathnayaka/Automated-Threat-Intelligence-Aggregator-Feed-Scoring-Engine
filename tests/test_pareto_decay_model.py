"""Unit tests for Pareto heavy-tailed decay model."""

from cti_core.scoring.pareto_decay_model import ParetoDecayModel


def test_pareto_survival_factor():
    # Age <= t_min -> factor 1.0
    assert ParetoDecayModel.survival_factor(1.0, "ipv4") == 1.0

    # Age > t_min (e.g. 10 days for IPv4, t_min=3.0)
    factor = ParetoDecayModel.survival_factor(10.0, "ipv4")
    assert 0.30 < factor < 0.50

    # Malware hashes have very slow heavy-tailed decay (alpha=0.40)
    hash_factor = ParetoDecayModel.survival_factor(60.0, "sha256")
    assert hash_factor > 0.70


def test_pareto_decayed_score():
    score = ParetoDecayModel.calculate_decayed_score(initial_score=90.0, age_days=15.0, ioc_type="domain")
    assert 40.0 < score < 80.0
