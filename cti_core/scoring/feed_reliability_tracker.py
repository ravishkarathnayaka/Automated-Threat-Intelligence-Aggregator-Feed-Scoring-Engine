"""Dynamic feed reliability rating and false-positive tracking engine."""

from typing import Dict, Optional


class FeedReliabilityTracker:
    """Tracks historical precision and false positive rates of external threat feeds."""

    def __init__(self, baseline_weights: Optional[Dict[str, float]] = None):
        self.stats: Dict[str, Dict[str, int]] = {}
        self.baseline_weights: Dict[str, float] = baseline_weights or {
            "virustotal": 0.95,
            "threatfox": 0.90,
            "urlhaus": 0.85,
            "spamhaus": 0.95,
            "blocklist_de": 0.75,
            "alienvault": 0.70,
        }

    def record_verification(self, feed_name: str, is_true_positive: bool = True) -> None:
        """Records an analyst verification or telemetry correlation feedback."""
        key = feed_name.lower().strip()
        if key not in self.stats:
            self.stats[key] = {"tp": 0, "fp": 0}

        if is_true_positive:
            self.stats[key]["tp"] += 1
        else:
            self.stats[key]["fp"] += 1

    def get_precision(self, feed_name: str) -> float:
        """Calculates smoothed Laplace precision for a threat feed."""
        key = feed_name.lower().strip()
        data = self.stats.get(key, {"tp": 0, "fp": 0})
        tp = data["tp"]
        fp = data["fp"]
        # Laplace smoothed precision
        return (tp + 1.0) / (tp + fp + 2.0)

    def get_dynamic_weight(self, feed_name: str) -> float:
        """Computes dynamic multiplier weight bounded between [0.2, 1.25]."""
        key = feed_name.lower().strip()
        base = self.baseline_weights.get(key, 0.70)
        if key not in self.stats:
            return round(base, 3)

        precision = self.get_precision(key)
        # Scale base weight by relative precision vs 0.80 benchmark
        multiplier = precision / 0.80
        adjusted = base * multiplier
        return round(max(0.20, min(1.25, adjusted)), 3)
