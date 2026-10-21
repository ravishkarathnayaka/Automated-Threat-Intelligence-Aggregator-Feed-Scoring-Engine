"""Unit tests for logistic sigmoid threat decay curves."""

from cti_core.scoring.decay_curves import LogisticSigmoidDecayModel


def test_sigmoid_decay_at_inflection():
    # At t = t0, multiplier is exactly 1 / (1 + e^0) = 0.5
    mult = LogisticSigmoidDecayModel.calculate_multiplier(age_days=5.0, inflection_days=5.0, steepness=0.5)
    assert abs(mult - 0.5) < 0.001

    score = LogisticSigmoidDecayModel.calculate_decayed_score(
        initial_score=80.0, age_days=5.0, custom_inflection=5.0
    )
    assert abs(score - 40.0) < 0.1


def test_sigmoid_decay_plateau_early_life():
    # Fresh indicators (t << t0) maintain almost 100% of their initial score
    mult = LogisticSigmoidDecayModel.calculate_multiplier(age_days=0.0, inflection_days=10.0, steepness=1.0)
    assert mult > 0.999


def test_sigmoid_decay_late_life_and_floor():
    # Old indicators collapse close to floor
    score = LogisticSigmoidDecayModel.calculate_decayed_score(
        initial_score=90.0,
        age_days=30.0,
        custom_inflection=5.0,
        steepness=1.0,
        floor_score=5.0,
    )
    assert score == 5.0
