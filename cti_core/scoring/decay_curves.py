"""Advanced decay curves for threat intelligence life cycles."""

import math
from typing import Dict, Optional


class LogisticSigmoidDecayModel:
    """Models threat life cycles using logistic sigmoid decay functions.

    Formula:
        Multiplier = 1.0 / (1.0 + exp(steepness * (age_days - inflection_days)))
        Decayed Score = initial_score * Multiplier
    """

    DEFAULT_INFLECTION_DAYS: Dict[str, float] = {
        "url": 2.0,
        "ipv4": 5.0,
        "ipv6": 5.0,
        "domain": 14.0,
        "cve": 60.0,
        "sha256": 120.0,
    }

    DEFAULT_STEEPNESS: float = 0.5  # Curve steepness

    @classmethod
    def calculate_multiplier(
        cls,
        age_days: float,
        inflection_days: float,
        steepness: float = DEFAULT_STEEPNESS,
    ) -> float:
        """Computes sigmoid decay factor [0.0, 1.0]."""
        if age_days < 0:
            return 1.0
        exponent = steepness * (age_days - inflection_days)
        # Prevent numerical overflow in exp
        if exponent > 50:
            return 0.0
        if exponent < -50:
            return 1.0
        return 1.0 / (1.0 + math.exp(exponent))

    @classmethod
    def calculate_decayed_score(
        cls,
        initial_score: float,
        age_days: float,
        ioc_type: str = "ipv4",
        custom_inflection: Optional[float] = None,
        steepness: float = DEFAULT_STEEPNESS,
        floor_score: float = 0.0,
    ) -> float:
        """Returns scored decay value under sigmoid life cycle."""
        if initial_score <= 0.0:
            return 0.0
        t0 = custom_inflection if custom_inflection is not None else cls.DEFAULT_INFLECTION_DAYS.get(ioc_type.lower(), 7.0)
        multiplier = cls.calculate_multiplier(age_days, t0, steepness=steepness)
        decayed = initial_score * multiplier
        return round(max(floor_score, decayed), 2)
