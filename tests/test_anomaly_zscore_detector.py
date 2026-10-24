"""Unit tests for rolling Z-score anomaly detector."""

from cti_core.scoring.anomaly_zscore_detector import AnomalyZScoreDetector


def test_anomaly_zscore_detection():
    # Baseline history around 50 +/- 5 indicators per hour
    history = [48.0, 52.0, 49.0, 51.0, 50.0, 53.0, 47.0]

    # Nominal observation: 51
    is_anomaly, z, desc = AnomalyZScoreDetector.evaluate_volume(history, 51.0)
    assert is_anomaly is False
    assert abs(z) < 1.5
    assert desc == "nominal_feed_volume"

    # Sudden surge: 120 (far above mean=50, std~2)
    is_anomaly, z, desc = AnomalyZScoreDetector.evaluate_volume(history, 120.0, threshold_z=3.0)
    assert is_anomaly is True
    assert z > 10.0
    assert "volumetric_surge_anomaly" in desc


def test_insufficient_history():
    is_anomaly, z, desc = AnomalyZScoreDetector.evaluate_volume([50.0, 52.0], 100.0)
    assert is_anomaly is False
    assert desc == "insufficient_history"
