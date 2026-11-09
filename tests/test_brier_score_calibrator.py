"""Unit tests for Brier Score quadratic proper scoring rule calibrator."""

from cti_core.scoring.brier_score_calibrator import BrierScoreCalibrator


def test_brier_score_calibration():
    # Accurate well-calibrated predictions
    good_pairs = [(0.92, 1), (0.88, 1), (0.05, 0), (0.95, 1)]
    bs, weight, desc = BrierScoreCalibrator.compute_brier_score(good_pairs)
    assert bs < 0.05
    assert weight > 0.95
    assert "well_calibrated" in desc

    # Overconfident wrong predictions
    bad_pairs = [(0.95, 0), (0.90, 0), (0.10, 1)]
    bs_bad, weight_bad, desc_bad = BrierScoreCalibrator.compute_brier_score(bad_pairs)
    assert bs_bad > 0.70
    assert weight_bad < 0.30
    assert "poorly_calibrated" in desc_bad
