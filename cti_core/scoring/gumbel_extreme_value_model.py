"""Gumbel distribution extreme value model for rare APT surges and indicator peak anomalies."""

import math
from typing import Dict, List, Optional, Tuple


class GumbelExtremeValueModel:
    """Models tail events and extreme value distributions using the Gumbel (Type-I EV) distribution.

    Used to detect statistically rare surges in attack indicator velocity and APT campaign spikes.
    """

    EULER_MASCHERONI = 0.5772156649015329

    def __init__(self, location_mu: float = 0.0, scale_beta: float = 1.0):
        if scale_beta <= 0:
            raise ValueError("scale_beta must be strictly positive")
        self.mu = location_mu
        self.beta = scale_beta

    @classmethod
    def fit_from_samples(cls, peaks: List[float]) -> "GumbelExtremeValueModel":
        """Estimates Gumbel parameters (mu, beta) from a series of observed peak maximums using Method of Moments."""
        if len(peaks) < 2:
            return cls(location_mu=peaks[0] if peaks else 0.0, scale_beta=1.0)

        n = len(peaks)
        mean_x = sum(peaks) / n
        variance = sum((x - mean_x) ** 2 for x in peaks) / (n - 1)
        std_x = math.sqrt(variance)

        if std_x == 0:
            std_x = 1e-4

        beta = (std_x * math.sqrt(6.0)) / math.pi
        mu = mean_x - (cls.EULER_MASCHERONI * beta)
        return cls(location_mu=mu, scale_beta=max(beta, 1e-6))

    def cumulative_distribution(self, x: float) -> float:
        """Calculates F(x) = exp(-exp(-(x - mu) / beta))."""
        z = (x - self.mu) / self.beta
        # Guard against overflow/underflow
        if z < -20.0:
            return 0.0
        elif z > 20.0:
            return 1.0
        return math.exp(-math.exp(-z))

    def exceedance_probability(self, x: float) -> float:
        """Calculates P(X >= x) = 1 - F(x)."""
        return max(0.0, min(1.0, 1.0 - self.cumulative_distribution(x)))

    def return_period(self, x: float) -> float:
        """Calculates estimated recurrence return period T = 1 / P(X >= x)."""
        p = self.exceedance_probability(x)
        if p <= 1e-7:
            return 10000000.0
        return round(1.0 / p, 2)

    def calculate_surge_score(self, current_value: float) -> Dict[str, float]:
        """Scores how anomalous a current observed volume is relative to historical extreme distributions."""
        p_exceed = self.exceedance_probability(current_value)
        # Low exceedance probability indicates extreme anomaly
        anomaly_score = round((1.0 - p_exceed) * 100.0, 2)
        return {
            "current_value": round(current_value, 2),
            "location_mu": round(self.mu, 4),
            "scale_beta": round(self.beta, 4),
            "exceedance_probability": round(p_exceed, 6),
            "return_period": self.return_period(current_value),
            "surge_anomaly_score": anomaly_score,
        }

    @classmethod
    def evaluate_surge(
        cls, historical_peaks: List[float], current_value: float
    ) -> Dict[str, float]:
        """Convenience evaluation method."""
        model = cls.fit_from_samples(historical_peaks)
        return model.calculate_surge_score(current_value)
