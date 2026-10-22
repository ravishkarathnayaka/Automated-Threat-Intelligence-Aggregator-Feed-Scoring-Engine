"""Unit tests for 1-D Kalman confidence filter."""

from cti_core.scoring.kalman_confidence_filter import KalmanConfidenceFilter


def test_kalman_filter_convergence():
    kf = KalmanConfidenceFilter(initial_confidence=50.0)
    # Repeated measurements of ~90 should steadily pull the state estimate up
    for _ in range(5):
        kf.predict()
        est, var = kf.update(90.0)

    assert est > 85.0
    # Uncertainty should decrease over multiple consistent measurements
    assert var < 10.0


def test_kalman_batch_filtering():
    measurements = [60.0, 75.0, 80.0, 85.0, 90.0]
    smoothed = KalmanConfidenceFilter.filter_batch(measurements, initial_score=50.0)
    assert len(smoothed) == 5
    assert smoothed[-1] > smoothed[0]
    assert smoothed[-1] > 80.0
