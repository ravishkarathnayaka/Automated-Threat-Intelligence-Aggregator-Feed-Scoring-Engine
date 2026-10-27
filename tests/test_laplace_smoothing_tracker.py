"""Unit tests for additive Laplace smoothing precision tracker."""

import pytest
from cti_core.scoring.laplace_smoothing_tracker import LaplaceSmoothingTracker


def test_invalid_parameters():
    with pytest.raises(ValueError):
        LaplaceSmoothingTracker(alpha=-0.1)
    with pytest.raises(ValueError):
        LaplaceSmoothingTracker(num_classes=1)


def test_sparse_feed_smoothing():
    # A feed with only 1 report and 1 true positive has raw precision 100%,
    # but with Laplace smoothing (1+1)/(1+2) = 2/3 = ~0.6667
    metrics = LaplaceSmoothingTracker.evaluate_feed(true_positives=1, total_reports=1, alpha=1.0)
    assert metrics["raw_precision"] == 1.0
    assert pytest.approx(metrics["smoothed_precision"], abs=0.01) == 0.6667
    assert metrics["confidence_score"] == 66.67


def test_large_sample_convergence():
    # As samples grow large, smoothed precision converges to raw precision
    metrics = LaplaceSmoothingTracker.evaluate_feed(true_positives=900, total_reports=1000, alpha=1.0)
    assert pytest.approx(metrics["smoothed_precision"], abs=0.005) == metrics["raw_precision"]
    assert metrics["uncertainty_span"] < 0.05
