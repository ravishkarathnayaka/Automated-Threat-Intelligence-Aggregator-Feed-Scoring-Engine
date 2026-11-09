"""Unit tests for Tabular CUSUM sequential change-point detector."""

from cti_core.scoring.cusum_changepoint_detector import CUSUMChangePointDetector


def test_cusum_burst_detection():
    # Nominal observations around mean=10, then sudden burst of 25s
    series = [9.0, 10.0, 11.0, 10.0, 25.0, 26.0, 24.0]
    alarm, max_s, traj, status = CUSUMChangePointDetector.detect_burst(
        series,
        target_mean=10.0,
        allowable_slack_k=2.0,
        decision_threshold_h=15.0,
    )
    assert alarm is True
    assert max_s >= 15.0
    assert len(traj) == len(series)
    assert "surge_detected" in status

    # Calm series
    calm = [8.0, 10.0, 9.0, 11.0, 10.0]
    alarm2, max_s2, _, status2 = CUSUMChangePointDetector.detect_burst(calm, target_mean=10.0)
    assert alarm2 is False
    assert max_s2 < 15.0
    assert status2 == "nominal_baseline_rate"
