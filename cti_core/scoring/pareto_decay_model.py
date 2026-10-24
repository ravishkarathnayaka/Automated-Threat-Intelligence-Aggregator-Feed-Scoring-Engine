"""Heavy-tailed Pareto power-law decay model for persistent APT threat infrastructure."""

import math
from typing import Dict


class ParetoDecayModel:
    """Models power-law decay where persistent long-tail threats retain confidence longer than exponential models.

    Survival function: S(t) = (t_min / max(t_min, t)) ^ alpha
    """

    # Default parameters per IoC type: (t_min_days, alpha_tail_index)
    TYPE_PARAMS: Dict[str, tuple] = {
        "ipv4": (3.0, 0.85),     # Sub-exponential tail for dormant C2 nodes
        "domain": (7.0, 0.70),   # APT domain parking resilience
        "sha256": (30.0, 0.40),  # Heavy tail: binary malware hashes remain hazardous for months
    }

    @classmethod
    def survival_factor(cls, age_days: float, ioc_type: str = "ipv4") -> float:
        """Calculates power-law survival multiplier in [0.0, 1.0]."""
        if age_days <= 0:
            return 1.0

        t_min, alpha = cls.TYPE_PARAMS.get(ioc_type.lower(), (3.0, 0.85))
        if age_days <= t_min:
            return 1.0

        factor = math.pow(t_min / age_days, alpha)
        return round(max(0.05, min(1.0, factor)), 4)

    @classmethod
    def calculate_decayed_score(
        cls,
        initial_score: float,
        age_days: float,
        ioc_type: str = "ipv4",
        floor: float = 10.0,
    ) -> float:
        """Applies Pareto decay to initial score."""
        factor = cls.survival_factor(age_days, ioc_type=ioc_type)
        decayed = initial_score * factor
        return round(max(floor, decayed), 2)
