"""Bayesian probability update model for indicator confidence scoring."""

import math
from typing import Dict, List, Optional


class BayesianScorer:
    """Updates threat indicator probability using sequential Bayesian likelihood ratios."""

    DEFAULT_PRIOR = 0.15  # Base rate that an unverified internet indicator is malicious

    # Likelihood ratios: (True Positive Rate / False Positive Rate)
    SOURCE_LR = {
        "virustotal": 18.0,
        "alienvault_otx": 12.0,
        "abuse_ch_threatfox": 22.0,
        "abuse_ch_urlhaus": 20.0,
        "spamhaus_drop": 30.0,
        "blocklist_de": 14.0,
        "vxvault": 19.0,
        "cins_army": 16.0,
        "internal_honeypot": 35.0,
    }
    DEFAULT_LR = 8.0

    @classmethod
    def probability_to_score(cls, prob: float) -> float:
        """Converts probability [0.0, 1.0] to confidence score [0.0, 100.0]."""
        clamped = max(0.0001, min(0.9999, prob))
        return round(clamped * 100.0, 2)

    @classmethod
    def update_probability(
        cls,
        sources: List[str],
        prior: float = DEFAULT_PRIOR,
        benign_confirmations: int = 0,
    ) -> float:
        """Calculates posterior probability given reporting sources and benign counter-evidence."""
        if not (0.001 <= prior <= 0.999):
            raise ValueError("Prior probability must be between 0.001 and 0.999")

        prior_odds = prior / (1.0 - prior)
        total_lr = 1.0

        for src in sources:
            key = src.lower().replace("-", "_")
            lr = cls.SOURCE_LR.get(key, cls.DEFAULT_LR)
            total_lr *= lr

        # Benign evidence (e.g. Alexa top 1000, Cisco Umbrella top 1M) strongly reduces odds
        if benign_confirmations > 0:
            total_lr *= math.pow(0.05, benign_confirmations)

        posterior_odds = prior_odds * total_lr
        posterior_prob = posterior_odds / (1.0 + posterior_odds)
        return max(0.0, min(1.0, posterior_prob))

    @classmethod
    def compute_bayesian_confidence(
        cls,
        sources: List[str],
        prior: float = DEFAULT_PRIOR,
        benign_confirmations: int = 0,
    ) -> float:
        """Returns 0-100 confidence score based on Bayesian posterior probability."""
        prob = cls.update_probability(sources, prior=prior, benign_confirmations=benign_confirmations)
        return cls.probability_to_score(prob)
