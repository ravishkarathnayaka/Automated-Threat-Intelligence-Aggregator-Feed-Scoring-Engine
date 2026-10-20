"""Unit tests for hysteresis reputation tier evaluator."""

from cti_core.models.indicator import ConfidenceTier
from cti_core.scoring.reputation_tiers import HysteresisTierEvaluator


def test_initial_tier_evaluation():
    assert HysteresisTierEvaluator.evaluate_tier(90.0) == ConfidenceTier.CRITICAL
    assert HysteresisTierEvaluator.evaluate_tier(75.0) == ConfidenceTier.HIGH
    assert HysteresisTierEvaluator.evaluate_tier(50.0) == ConfidenceTier.MEDIUM
    assert HysteresisTierEvaluator.evaluate_tier(20.0) == ConfidenceTier.LOW


def test_hysteresis_dampening_downward():
    # Indicator was HIGH (threshold 70.0). It dips to 69.0 (within 2.0 buffer)
    tier = HysteresisTierEvaluator.evaluate_tier(
        new_score=69.0,
        current_tier=ConfidenceTier.HIGH,
        buffer_points=2.0,
    )
    # Stays HIGH due to hysteresis buffer
    assert tier == ConfidenceTier.HIGH

    # Dips below 70.0 - 2.0 = 68.0
    tier_dropped = HysteresisTierEvaluator.evaluate_tier(
        new_score=67.5,
        current_tier=ConfidenceTier.HIGH,
        buffer_points=2.0,
    )
    assert tier_dropped == ConfidenceTier.MEDIUM


def test_hysteresis_dampening_upward():
    # Indicator was MEDIUM. It reaches 71.0 (needs 70.0 + 2.0 = 72.0 to transition up)
    tier = HysteresisTierEvaluator.evaluate_tier(
        new_score=71.0,
        current_tier=ConfidenceTier.MEDIUM,
        buffer_points=2.0,
    )
    assert tier == ConfidenceTier.MEDIUM

    # Rises to 73.0 (above 72.0)
    tier_promoted = HysteresisTierEvaluator.evaluate_tier(
        new_score=73.0,
        current_tier=ConfidenceTier.MEDIUM,
        buffer_points=2.0,
    )
    assert tier_promoted == ConfidenceTier.HIGH
