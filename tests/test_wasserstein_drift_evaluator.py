"""Unit tests for 1-D Wasserstein (Earth Mover's) Distance drift evaluator."""

from cti_core.scoring.wasserstein_drift_evaluator import WassersteinDriftEvaluator


def test_wasserstein_drift_evaluation():
    baseline = [70.0, 72.0, 75.0, 78.0, 80.0]
    same = [70.0, 72.0, 75.0, 78.0, 80.0]
    w1_zero, drifted_zero, _ = WassersteinDriftEvaluator.compute_w1_distance(baseline, same)
    assert w1_zero == 0.0
    assert drifted_zero is False

    # Shifted distribution by +25 points
    shifted = [x + 25.0 for x in baseline]
    w1_shift, drifted_shift, desc = WassersteinDriftEvaluator.compute_w1_distance(baseline, shifted)
    assert abs(w1_shift - 25.0) < 0.1
    assert drifted_shift is True
    assert "severe" in desc
