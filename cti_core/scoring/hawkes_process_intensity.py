"""Hawkes Self-Exciting Point Process model for coordinated APT attack and botnet burst intensity."""

import math
from typing import Iterable, List, Tuple


class HawkesProcessIntensityModel:
    """Computes conditional intensity lambda(t) of a univariate Hawkes self-exciting point process.

    Formula: lambda(t) = mu + sum_{t_i < t} alpha * exp(-beta * (t - t_i))
    """

    @classmethod
    def compute_intensity(
        cls,
        event_timestamps: Iterable[float],
        evaluation_time: float = 0.0,
        baseline_mu: float = 0.10,
        excitation_alpha: float = 0.85,
        decay_beta: float = 1.20,
    ) -> Tuple[float, float, float, str]:
        """Calculates Hawkes conditional intensity and branching ratio n* = alpha / beta.

        Returns:
            Tuple[float, float, float, str]: (intensity_lambda, branching_ratio, risk_boost, regime)
        """
        times: List[float] = sorted(float(t) for t in event_timestamps)
        if not times:
            return round(baseline_mu, 4), round(excitation_alpha / decay_beta, 4), 0.0, "quiescent_baseline"

        t_eval = max(float(evaluation_time), times[-1])
        excitation_sum = 0.0
        for t_i in times:
            if t_i <= t_eval:
                dt = t_eval - t_i
                excitation_sum += excitation_alpha * math.exp(-decay_beta * dt)

        lam = round(baseline_mu + excitation_sum, 4)
        branching_ratio = round(excitation_alpha / max(0.001, decay_beta), 4)

        # Convert conditional intensity into a 0-35 point threat score boost
        boost = round(min(35.0, max(0.0, (lam - baseline_mu) * 8.0)), 2)

        if lam >= baseline_mu + 2.5:
            regime = "supercritical_self_exciting_apt_swarm"
        elif lam >= baseline_mu + 0.8:
            regime = "elevated_clustered_campaign_activity"
        else:
            regime = "subcritical_background_noise"

        return lam, branching_ratio, boost, regime
