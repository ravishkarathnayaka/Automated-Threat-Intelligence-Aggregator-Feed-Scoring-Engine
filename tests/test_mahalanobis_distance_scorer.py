"""Unit tests for Mahalanobis distance multivariate outlier detector."""

import pytest
from cti_core.scoring.mahalanobis_distance_scorer import MahalanobisDistanceScorer


def test_fit_and_distance_at_mean():
    # Samples centered around (10, 20)
    samples = [
        [10.0, 20.0],
        [9.5, 19.5],
        [10.5, 20.5],
        [10.2, 19.8],
        [9.8, 20.2],
    ]
    model = MahalanobisDistanceScorer().fit(samples)
    # Point at the mean should have distance close to 0
    d_mean = model.distance([10.0, 20.0])
    assert pytest.approx(d_mean, abs=0.1) == 0.0


def test_outlier_detection():
    samples = [
        [10.0, 20.0],
        [9.5, 19.5],
        [10.5, 20.5],
        [10.2, 19.8],
        [9.8, 20.2],
    ]
    # Far-away outlier
    res = MahalanobisDistanceScorer.evaluate(samples, [50.0, 100.0])
    assert res["is_outlier"] is True
    assert res["mahalanobis_distance"] > 3.0
    assert res["anomaly_score"] > 80.0


def test_dimension_mismatch_raises():
    samples = [[1.0, 2.0], [2.0, 3.0]]
    model = MahalanobisDistanceScorer().fit(samples)
    with pytest.raises(ValueError):
        model.distance([1.0, 2.0, 3.0])
