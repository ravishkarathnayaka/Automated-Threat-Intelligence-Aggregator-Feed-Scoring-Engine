"""1-D Wasserstein (Earth Mover's) Distance feed distribution drift evaluator."""

from typing import Iterable, List, Tuple


class WassersteinDriftEvaluator:
    """Computes the 1-Wasserstein distance W_1(P, Q) between empirical score distributions."""

    @classmethod
    def compute_w1_distance(
        cls,
        baseline_scores: Iterable[float],
        current_scores: Iterable[float],
    ) -> Tuple[float, bool, str]:
        """Calculates exact 1-D Earth Mover's Distance via sorted quantile L1 integration.

        Args:
            baseline_scores: Reference confidence scores (0-100 scale).
            current_scores: Current window confidence scores (0-100 scale).

        Returns:
            Tuple[float, bool, str]: (w1_distance, is_drifted, classification)
        """
        u: List[float] = sorted(float(x) for x in baseline_scores)
        v: List[float] = sorted(float(x) for x in current_scores)

        if not u or not v:
            return 0.0, False, "insufficient_samples"

        # Evaluate quantile function at N = max(len(u), len(v), 100) grid points
        n_steps = max(len(u), len(v), 100)
        total_diff = 0.0
        for i in range(n_steps):
            q = (i + 0.5) / n_steps
            idx_u = min(len(u) - 1, int(q * len(u)))
            idx_v = min(len(v) - 1, int(q * len(v)))
            total_diff += abs(u[idx_u] - v[idx_v])

        w1 = round(total_diff / n_steps, 4)
        if w1 >= 20.0:
            return w1, True, "severe_wasserstein_regime_drift"
        if w1 >= 10.0:
            return w1, True, "moderate_wasserstein_distribution_shift"

        return w1, False, "stable_wasserstein_distribution"
