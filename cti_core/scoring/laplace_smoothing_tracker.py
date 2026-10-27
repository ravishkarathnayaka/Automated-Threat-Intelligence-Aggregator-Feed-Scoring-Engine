"""Additive Laplace smoothing estimator for feed precision and sparse sample calibration."""

import math
from typing import Dict, Tuple


class LaplaceSmoothingTracker:
    """Estimates calibrated true positive precision using additive Laplace / Lidstone smoothing.

    Prevents 0% or 100% false extremes when feeds have very few samples (sparse data problem).
    """

    def __init__(self, alpha: float = 1.0, num_classes: int = 2):
        """Initializes with smoothing parameter alpha (Laplace=1.0, Lidstone=0.5) and num_classes (default 2: TP/FP)."""
        if alpha < 0:
            raise ValueError("alpha smoothing parameter must be non-negative")
        if num_classes < 2:
            raise ValueError("num_classes must be at least 2")
        self.alpha = alpha
        self.num_classes = num_classes

    def smoothed_precision(self, true_positives: int, total_reports: int) -> float:
        """Calculates smoothed precision: (TP + alpha) / (Total + alpha * K)."""
        tp = max(0, true_positives)
        total = max(tp, total_reports)
        numerator = tp + self.alpha
        denominator = total + (self.alpha * self.num_classes)
        return round(numerator / denominator, 4)

    def confidence_interval(
        self, true_positives: int, total_reports: int, z: float = 1.96
    ) -> Tuple[float, float]:
        """Calculates Wilson-Laplace adjusted normal approximation confidence interval."""
        p_hat = self.smoothed_precision(true_positives, total_reports)
        n = total_reports + (self.alpha * self.num_classes)
        margin = z * math.sqrt((p_hat * (1.0 - p_hat)) / n)
        return (
            round(max(0.0, p_hat - margin), 4),
            round(min(1.0, p_hat + margin), 4),
        )

    @classmethod
    def evaluate_feed(
        cls,
        true_positives: int,
        total_reports: int,
        alpha: float = 1.0,
    ) -> Dict[str, float]:
        """Convenience method returning comprehensive precision metrics."""
        tracker = cls(alpha=alpha, num_classes=2)
        smoothed = tracker.smoothed_precision(true_positives, total_reports)
        ci_lower, ci_upper = tracker.confidence_interval(true_positives, total_reports)
        raw_precision = (
            round(true_positives / total_reports, 4) if total_reports > 0 else 0.0
        )
        return {
            "raw_precision": raw_precision,
            "smoothed_precision": smoothed,
            "confidence_score": round(smoothed * 100.0, 2),
            "ci_lower": ci_lower,
            "ci_upper": ci_upper,
            "uncertainty_span": round(ci_upper - ci_lower, 4),
        }
