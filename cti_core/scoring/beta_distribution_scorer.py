"""Beta-Binomial conjugate Bayesian threat confidence and uncertainty model."""

from typing import Dict, Tuple


class BetaDistributionScorer:
    """Computes posterior threat confidence and epistemic variance using conjugate Beta-Binomial updates."""

    def __init__(self, prior_alpha: float = 1.0, prior_beta: float = 4.0):
        """Initializes with prior belief (default skewed toward benign: E[p] = 1/(1+4) = 0.20)."""
        self.alpha = prior_alpha
        self.beta = prior_beta

    def update(self, malicious_reports: int, benign_reports: int) -> Tuple[float, float]:
        """Incorporates new evidence observations and updates Beta hyperparameters.

        Args:
            malicious_reports: Count of feed/sensor detections confirming malicious activity (successes).
            benign_reports: Count of whitelist or false-positive confirmations (failures).

        Returns:
            Tuple[float, float]: (posterior_mean, posterior_variance)
        """
        self.alpha += max(0, malicious_reports)
        self.beta += max(0, benign_reports)

        mean = self.alpha / (self.alpha + self.beta)
        variance = (self.alpha * self.beta) / (
            ((self.alpha + self.beta) ** 2) * (self.alpha + self.beta + 1.0)
        )
        return round(mean, 4), round(variance, 6)

    def to_confidence_score(self) -> float:
        """Converts posterior mean to standard 0-100 confidence score."""
        mean = self.alpha / (self.alpha + self.beta)
        return round(mean * 100.0, 2)

    @classmethod
    def calculate_score(
        cls,
        malicious_count: int,
        benign_count: int,
        prior_alpha: float = 1.0,
        prior_beta: float = 4.0,
    ) -> Dict[str, float]:
        """Static convenience method computing posterior metrics."""
        model = cls(prior_alpha=prior_alpha, prior_beta=prior_beta)
        mean, var = model.update(malicious_count, benign_count)
        return {
            "alpha": model.alpha,
            "beta": model.beta,
            "posterior_probability": mean,
            "epistemic_variance": var,
            "confidence_score": model.to_confidence_score(),
        }
