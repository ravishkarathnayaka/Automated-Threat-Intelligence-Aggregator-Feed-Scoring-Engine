"""Rolling Z-Score anomaly detector for feed indicator volume and surge monitoring."""

import math
from typing import List, Tuple


class AnomalyZScoreDetector:
    """Detects statistical anomalies and sudden volumetric surges in incoming threat feeds."""

    @classmethod
    def compute_stats(cls, series: List[float]) -> Tuple[float, float]:
        """Calculates arithmetic mean and sample standard deviation."""
        n = len(series)
        if n < 2:
            return (series[0], 0.0) if n == 1 else (0.0, 0.0)

        mean = sum(series) / n
        variance = sum((x - mean) ** 2 for x in series) / (n - 1)
        std_dev = math.sqrt(variance)
        return mean, std_dev

    @classmethod
    def evaluate_volume(
        cls,
        history: List[float],
        current_observation: float,
        threshold_z: float = 3.0,
    ) -> Tuple[bool, float, str]:
        """Evaluates whether current observation is a statistical surge anomaly (|Z| > threshold).

        Returns:
            Tuple[bool, float, str]: (is_anomaly, z_score, explanation)
        """
        if len(history) < 3:
            return False, 0.0, "insufficient_history"

        mean, std = cls.compute_stats(history)
        if std == 0.0:
            if current_observation == mean:
                return False, 0.0, "normal_invariant_history"
            return True, 99.0, "deviation_from_zero_variance"

        z = (current_observation - mean) / std

        if z >= threshold_z:
            return True, round(z, 2), f"volumetric_surge_anomaly (Z={round(z, 2)} > {threshold_z})"
        elif z <= -threshold_z:
            return True, round(z, 2), f"feed_drop_outage (Z={round(z, 2)})"

        return False, round(z, 2), "nominal_feed_volume"
