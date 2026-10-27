"""Domain Generation Algorithm (DGA) Hellinger distance probability metric classifier."""

import math
from typing import Dict, Tuple


class DGAHellingerClassifier:
    """Classifies DGAs using Hellinger distance between domain character distribution and standard natural language."""

    # Standard English character unigram frequencies (normalized)
    ENGLISH_UNIGRAMS: Dict[str, float] = {
        'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070,
        'n': 0.067, 's': 0.063, 'h': 0.061, 'r': 0.060, 'd': 0.043,
        'l': 0.040, 'c': 0.028, 'u': 0.028, 'm': 0.024, 'w': 0.024,
        'f': 0.022, 'g': 0.020, 'y': 0.020, 'p': 0.019, 'b': 0.015,
        'v': 0.010, 'k': 0.008, 'j': 0.002, 'x': 0.001, 'q': 0.001,
        'z': 0.001,
    }

    @classmethod
    def compute_hellinger_distance(cls, domain: str) -> float:
        """Calculates Hellinger distance H(P, Q) in range [0.0, 1.0]."""
        if not domain:
            return 0.0

        label = domain.split(".")[0].lower()
        # Filter alphabet chars
        chars = [c for c in label if 'a' <= c <= 'z']
        if not chars:
            return 1.0

        total = len(chars)
        counts: Dict[str, int] = {}
        for c in chars:
            counts[c] = counts.get(c, 0) + 1

        p_dist = {c: counts.get(c, 0) / total for c in cls.ENGLISH_UNIGRAMS}

        sq_diff_sum = 0.0
        for c, q in cls.ENGLISH_UNIGRAMS.items():
            p = p_dist[c]
            sq_diff_sum += (math.sqrt(p) - math.sqrt(q)) ** 2

        hellinger = math.sqrt(sq_diff_sum) / math.sqrt(2)
        return round(min(1.0, hellinger), 4)

    @classmethod
    def evaluate(cls, domain: str) -> Tuple[bool, float, float, str]:
        """Evaluates whether a domain is an algorithmically generated candidate.

        Returns:
            Tuple[bool, float, float, str]: (is_dga, hellinger_distance, penalty_score, classification)
        """
        dist = cls.compute_hellinger_distance(domain)
        if dist >= 0.65:
            return True, dist, 35.0, "high_hellinger_dga_entropy"
        elif dist >= 0.55:
            return True, dist, 20.0, "suspected_dga_character_distribution"

        return False, dist, 0.0, "natural_character_distribution"
