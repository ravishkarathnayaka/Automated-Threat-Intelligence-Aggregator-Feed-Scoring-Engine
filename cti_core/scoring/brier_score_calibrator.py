"""Brier Score Quadratic Proper Scoring Rule for threat feed calibration and forecasting accuracy."""

from typing import Iterable, Tuple


class BrierScoreCalibrator:
    """Evaluates probabilistic calibration of threat feeds using the Brier quadratic scoring rule."""

    @classmethod
    def compute_brier_score(
        cls,
        forecasts_and_outcomes: Iterable[Tuple[float, int]],
    ) -> Tuple[float, float, str]:
        """Computes Brier Score BS = (1/N) * sum((f_i - o_i)^2).

        Args:
            forecasts_and_outcomes: Iterable of (forecast_prob_0_to_1, actual_binary_outcome_0_or_1).

        Returns:
            Tuple[float, float, str]: (brier_score, calibrated_reliability_weight, classification)
        """
        pairs = list(forecasts_and_outcomes)
        if not pairs:
            return 0.25, 0.50, "uncalibrated_prior"

        sq_errors = []
        for prob, outcome in pairs:
            p = max(0.0, min(1.0, float(prob)))
            o = 1.0 if int(outcome) > 0 else 0.0
            sq_errors.append((p - o) ** 2)

        bs = round(sum(sq_errors) / len(sq_errors), 4)
        # Convert Brier score [0=perfect, 1=worst] into reliability weight [0.1, 1.0]
        weight = round(max(0.10, 1.0 - bs), 4)

        if bs <= 0.08:
            return bs, weight, "well_calibrated_authoritative_feed"
        if bs <= 0.22:
            return bs, weight, "moderately_calibrated_feed"

        return bs, weight, "poorly_calibrated_overconfident_feed"
