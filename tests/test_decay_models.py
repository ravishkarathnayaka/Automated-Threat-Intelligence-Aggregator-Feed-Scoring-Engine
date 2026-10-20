"""Unit tests for half-life scoring decay model."""

import pytest
from cti_core.scoring.decay_models import HalfLifeDecayModel


def test_zero_age_no_decay():
    score = HalfLifeDecayModel.calculate_decayed_score(100.0, age_days=0.0, ioc_type="ipv4")
    assert score == 100.0


def test_exact_half_life():
    # IPv4 default half life is 7 days
    score = HalfLifeDecayModel.calculate_decayed_score(80.0, age_days=7.0, ioc_type="ipv4")
    assert pytest.approx(score, 0.1) == 40.0


def test_double_half_life():
    # URL default half life is 3 days -> 6 days is 2 half-lives -> 0.25
    score = HalfLifeDecayModel.calculate_decayed_score(100.0, age_days=6.0, ioc_type="url")
    assert pytest.approx(score, 0.1) == 25.0


def test_custom_half_life_and_floor():
    score = HalfLifeDecayModel.calculate_decayed_score(
        100.0,
        age_days=100.0,
        custom_half_life=10.0,
        min_residual_score=15.0,
    )
    # 10 half lives would normally be ~0.09, but min_residual_score is 15.0
    assert score == 15.0


def test_hash_persistence():
    # File hashes decay much slower (180 days half life)
    score_url = HalfLifeDecayModel.calculate_decayed_score(90.0, age_days=30.0, ioc_type="url")
    score_hash = HalfLifeDecayModel.calculate_decayed_score(90.0, age_days=30.0, ioc_type="sha256")
    assert score_hash > score_url
