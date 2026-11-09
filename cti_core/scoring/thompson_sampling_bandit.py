"""Thompson Sampling Multi-Armed Bandit adaptive threat feed polling scheduler."""

import math
from typing import Dict, List, Tuple


class ThompsonSamplingBandit:
    """Optimizes threat feed polling priority using Beta-posterior Thompson Sampling and UCB indices."""

    def __init__(self) -> None:
        # Maps feed_name -> (alpha_successes, beta_failures)
        self.arms: Dict[str, Tuple[float, float]] = {}

    def register_feed(self, feed_name: str, alpha: float = 1.0, beta: float = 1.0) -> None:
        """Initializes Beta(alpha, beta) prior for a threat feed arm."""
        self.arms[feed_name] = (max(0.1, float(alpha)), max(0.1, float(beta)))

    def record_outcome(self, feed_name: str, actionable_hits: int, false_positives: int) -> None:
        """Updates Beta posterior parameters for a polled feed."""
        a, b = self.arms.get(feed_name, (1.0, 1.0))
        self.arms[feed_name] = (a + max(0, int(actionable_hits)), b + max(0, int(false_positives)))

    def rank_feeds_deterministic(self) -> List[Dict[str, object]]:
        """Ranks feeds by posterior mean + 1-sigma epistemic exploration bonus."""
        rankings = []
        for name, (a, b) in self.arms.items():
            total = a + b
            mean = a / total
            variance = (a * b) / ((total**2) * (total + 1.0))
            std_dev = math.sqrt(variance)
            ucb_score = min(1.0, mean + std_dev)
            rankings.append(
                {
                    "feed_name": name,
                    "posterior_mean": round(mean, 4),
                    "epistemic_std": round(std_dev, 4),
                    "priority_index": round(ucb_score * 100.0, 2),
                }
            )
        rankings.sort(key=lambda item: float(item["priority_index"]), reverse=True)  # type: ignore
        return rankings
