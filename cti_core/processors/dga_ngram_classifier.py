"""Domain bigram transition probability classifier for advanced DGA detection."""

import math
from typing import Dict, Tuple


class DGANgramClassifier:
    """Evaluates lexical plausibility using English character bigram log-likelihood."""

    # High frequency English bigram log frequencies
    COMMON_BIGRAMS = {
        "th", "he", "in", "er", "an", "re", "ed", "on", "es", "st", "en", "at",
        "to", "nt", "ha", "nd", "ou", "ea", "ng", "as", "or", "ti", "is", "et",
        "it", "ar", "te", "se", "hi", "of", "co", "om", "al", "de", "ch", "ro",
    }

    # Extremely rare / unnatural transition pairs
    RARE_BIGRAMS = {
        "qx", "zx", "vk", "qj", "xj", "zj", "jq", "vq", "jz", "wq", "bx", "cx",
        "dx", "fx", "gx", "hx", "jx", "kx", "lx", "px", "rx", "sx", "tx", "vx",
    }

    @classmethod
    def evaluate(cls, domain: str) -> Tuple[float, str]:
        """Calculates transition score for a domain label.

        Returns:
            Tuple[float, str]: (anomaly_score [0-100], reason)
        """
        if not domain:
            return 0.0, "empty_domain"

        # Extract SLD
        parts = domain.lower().strip().split(".")
        sld = parts[0] if len(parts) >= 1 else domain

        # Filter to alpha characters
        clean_chars = "".join(c for c in sld if c.isalpha())
        if len(clean_chars) < 4:
            return 0.0, "label_too_short"

        total_bigrams = len(clean_chars) - 1
        rare_count = 0
        common_count = 0

        for i in range(total_bigrams):
            pair = clean_chars[i : i + 2]
            if pair in cls.RARE_BIGRAMS:
                rare_count += 1
            elif pair in cls.COMMON_BIGRAMS:
                common_count += 1

        rare_ratio = rare_count / total_bigrams
        common_ratio = common_count / total_bigrams

        if rare_ratio >= 0.25:
            return 85.0, f"high_frequency_rare_bigrams ({rare_count}/{total_bigrams})"

        if common_ratio < 0.15 and len(clean_chars) >= 8:
            return 70.0, "low_natural_english_transition_density"

        return 10.0, "natural_bigram_transitions"
