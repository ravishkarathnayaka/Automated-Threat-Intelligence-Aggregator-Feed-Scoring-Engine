"""Hysteresis buffer tier evaluator to prevent perimeter blocklist flapping."""

from typing import Optional
from cti_core.models.indicator import ConfidenceTier


class HysteresisTierEvaluator:
    """Applies hysteresis deadbands when transitioning confidence tiers to avoid flapping.

    Thresholds:
        CRITICAL: 85.0
        HIGH:     70.0
        MEDIUM:   40.0
        LOW:      < 40.0
    """

    DEFAULT_BUFFER = 2.0  # Points buffer required to transition tier

    @classmethod
    def evaluate_tier(
        cls,
        new_score: float,
        current_tier: Optional[ConfidenceTier] = None,
        buffer_points: float = DEFAULT_BUFFER,
    ) -> ConfidenceTier:
        """Derive confidence tier with hysteresis stabilization."""
        score = max(0.0, min(100.0, float(new_score)))

        if current_tier is None:
            if score >= 85.0:
                return ConfidenceTier.CRITICAL
            elif score >= 70.0:
                return ConfidenceTier.HIGH
            elif score >= 40.0:
                return ConfidenceTier.MEDIUM
            return ConfidenceTier.LOW

        # Downward transitions require score to drop below threshold - buffer
        # Upward transitions require score to rise above threshold + buffer
        if current_tier == ConfidenceTier.CRITICAL:
            if score < (85.0 - buffer_points):
                return cls.evaluate_tier(score, current_tier=None)
            return ConfidenceTier.CRITICAL

        if current_tier == ConfidenceTier.HIGH:
            if score >= (85.0 + buffer_points):
                return ConfidenceTier.CRITICAL
            if score < (70.0 - buffer_points):
                return cls.evaluate_tier(score, current_tier=None)
            return ConfidenceTier.HIGH

        if current_tier == ConfidenceTier.MEDIUM:
            if score >= (70.0 + buffer_points):
                return ConfidenceTier.HIGH
            if score < (40.0 - buffer_points):
                return ConfidenceTier.LOW
            return ConfidenceTier.MEDIUM

        # Current tier is LOW
        if score >= (40.0 + buffer_points):
            return cls.evaluate_tier(score, current_tier=None)
        return ConfidenceTier.LOW
