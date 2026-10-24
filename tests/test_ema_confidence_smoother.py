"""Unit tests for EMA confidence smoother."""

from cti_core.scoring.ema_confidence_smoother import EMASmoother


def test_ema_computation():
    series = [50.0, 60.0, 70.0, 80.0]
    ema = EMASmoother.compute_ema(series, alpha=0.5)

    assert len(ema) == 4
    assert ema[0] == 50.0
    # 0.5 * 60 + 0.5 * 50 = 55
    assert ema[1] == 55.0
    # 0.5 * 70 + 0.5 * 55 = 62.5
    assert ema[2] == 62.5


def test_dual_window_divergence():
    # Accelerating upward threat trend
    series = [40.0, 50.0, 70.0, 90.0, 95.0]
    fast, slow, div = EMASmoother.dual_window_divergence(series, fast_alpha=0.5, slow_alpha=0.1)

    assert fast > slow
    assert div > 0.0
