"""Dual-window Exponential Moving Average (EMA) confidence and volatility smoother."""

from typing import List, Tuple


class EMASmoother:
    """Computes Exponential Moving Average (EMA) and signal volatility for dynamic confidence tracking."""

    @classmethod
    def compute_ema(cls, series: List[float], alpha: float = 0.2) -> List[float]:
        """Calculates single-window EMA for a sequence of observations."""
        if not series:
            return []

        ema_values: List[float] = [series[0]]
        for val in series[1:]:
            new_ema = alpha * val + (1.0 - alpha) * ema_values[-1]
            ema_values.append(round(new_ema, 2))
        return ema_values

    @classmethod
    def dual_window_divergence(
        cls,
        series: List[float],
        fast_alpha: float = 0.4,
        slow_alpha: float = 0.1,
    ) -> Tuple[float, float, float]:
        """Computes fast EMA, slow EMA, and divergence spread for trend detection.

        Returns:
            Tuple[float, float, float]: (latest_fast_ema, latest_slow_ema, divergence)
        """
        if not series:
            return 0.0, 0.0, 0.0

        fast = cls.compute_ema(series, fast_alpha)[-1]
        slow = cls.compute_ema(series, slow_alpha)[-1]
        divergence = round(fast - slow, 2)
        return fast, slow, divergence
