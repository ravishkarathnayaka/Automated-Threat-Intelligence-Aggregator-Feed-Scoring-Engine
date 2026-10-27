"""Dirichlet-Multinomial Bayesian multi-category threat indicator classifier."""

import math
from typing import Dict, Optional, Tuple


class DirichletMultinomialScorer:
    """Computes posterior multinomial categorical distributions and entropy over threat classifications."""

    DEFAULT_CATEGORIES = ("c2", "malware", "phishing", "scanner", "benign")
    DEFAULT_WEIGHTS = {
        "c2": 1.0,
        "malware": 0.95,
        "phishing": 0.85,
        "scanner": 0.30,
        "benign": 0.0,
    }

    def __init__(self, prior_alphas: Optional[Dict[str, float]] = None):
        """Initializes Dirichlet prior hyperparameters alpha for each category."""
        if prior_alphas is None:
            self.alphas: Dict[str, float] = {cat: 1.0 for cat in self.DEFAULT_CATEGORIES}
        else:
            self.alphas = {cat: float(prior_alphas.get(cat, 1.0)) for cat in self.DEFAULT_CATEGORIES}

    def update(self, observations: Dict[str, int]) -> Dict[str, float]:
        """Updates Dirichlet posterior with observed category event counts.

        Returns:
            Dict[str, float]: Posterior probabilities E[p_k] = alpha_k / sum(alpha).
        """
        for cat, count in observations.items():
            if cat in self.alphas:
                self.alphas[cat] += max(0, int(count))

        alpha_0 = sum(self.alphas.values())
        return {cat: round(alpha / alpha_0, 4) for cat, alpha in self.alphas.items()}

    def compute_category_variances(self) -> Dict[str, float]:
        """Calculates epistemic variance for each category."""
        alpha_0 = sum(self.alphas.values())
        variances = {}
        for cat, alpha_k in self.alphas.items():
            var = (alpha_k * (alpha_0 - alpha_k)) / ((alpha_0**2) * (alpha_0 + 1.0))
            variances[cat] = round(var, 6)
        return variances

    def compute_entropy(self) -> float:
        """Calculates categorical entropy H(P) reflecting classification uncertainty."""
        alpha_0 = sum(self.alphas.values())
        entropy = 0.0
        for alpha_k in self.alphas.values():
            p_k = alpha_k / alpha_0
            if p_k > 0:
                entropy -= p_k * math.log(p_k)
        return round(entropy, 4)

    def composite_threat_score(self, weights: Optional[Dict[str, float]] = None) -> float:
        """Computes risk-weighted threat score (0-100 scale)."""
        w = weights or self.DEFAULT_WEIGHTS
        alpha_0 = sum(self.alphas.values())
        score = 0.0
        for cat, alpha_k in self.alphas.items():
            prob = alpha_k / alpha_0
            score += prob * w.get(cat, 0.5)
        return round(score * 100.0, 2)

    @classmethod
    def classify(
        cls,
        observations: Dict[str, int],
        prior_alphas: Optional[Dict[str, float]] = None,
    ) -> Dict[str, object]:
        """Convenience method to fit and classify threat categories."""
        model = cls(prior_alphas=prior_alphas)
        probabilities = model.update(observations)
        variances = model.compute_category_variances()
        dominant_cat = max(probabilities.items(), key=lambda item: item[1])[0]
        return {
            "probabilities": probabilities,
            "variances": variances,
            "dominant_category": dominant_cat,
            "entropy": model.compute_entropy(),
            "composite_threat_score": model.composite_threat_score(),
        }
