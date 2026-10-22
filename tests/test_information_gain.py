"""Unit tests for Shannon information gain evaluator."""

from cti_core.scoring.information_gain_evaluator import InformationGainEvaluator


def test_binary_entropy():
    # Maximum uncertainty at p = 0.5 -> 1.0 bit
    h = InformationGainEvaluator.binary_entropy(0.5)
    assert abs(h - 1.0) < 1e-4

    # Certainty at p = 0.0 or 1.0 -> 0.0 bits
    assert InformationGainEvaluator.binary_entropy(0.0) < 0.001
    assert InformationGainEvaluator.binary_entropy(1.0) < 0.001


def test_information_gain_reduction():
    # Moving from high uncertainty (p=0.5) to high confidence (p=0.99) yields positive information gain
    ig = InformationGainEvaluator.calculate_information_gain(0.5, 0.99)
    assert ig > 0.8  # Almost 1 bit of information gained

    boost = InformationGainEvaluator.calculate_entropy_weighted_boost(feed_count=3, prior_p=0.5, posterior_p=0.99)
    assert boost > 10.0
