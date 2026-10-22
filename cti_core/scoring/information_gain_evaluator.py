"""Shannon information gain evaluator for multi-feed threat corroboration."""

import math
from typing import List


class InformationGainEvaluator:
    """Calculates information-theoretic entropy reduction from sequential feed sightings."""

    @classmethod
    def binary_entropy(cls, p: float) -> float:
        """Computes binary Shannon entropy H(p) in bits."""
        p_clamped = max(1e-6, min(1.0 - 1e-6, p))
        return -(p_clamped * math.log2(p_clamped) + (1.0 - p_clamped) * math.log2(1.0 - p_clamped))

    @classmethod
    def calculate_information_gain(
        cls,
        prior_probability: float,
        posterior_probability: float,
    ) -> float:
        """Calculates mutual information / entropy reduction: IG = H(prior) - H(posterior)."""
        h_prior = cls.binary_entropy(prior_probability)
        h_post = cls.binary_entropy(posterior_probability)
        return round(max(0.0, h_prior - h_post), 4)

    @classmethod
    def calculate_entropy_weighted_boost(
        cls,
        feed_count: int,
        prior_p: float = 0.20,
        posterior_p: float = 0.85,
    ) -> float:
        """Generates dynamic score boost scaled by information bits gained."""
        ig = cls.calculate_information_gain(prior_p, posterior_p)
        # 1 bit of information gain corresponds to maximum certainty
        boost = ig * (10.0 + min(feed_count, 5) * 2.0)
        return round(boost, 2)
