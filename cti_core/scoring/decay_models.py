"""Configurable mathematical decay models for threat intelligence indicators."""

from typing import Dict, Optional


class HalfLifeDecayModel:
    """Calculates indicator score decay using physical half-life exponential formulas.

    Formula:
        Multiplier = (0.5) ** (age_days / half_life_days)
        Decayed Score = initial_score * Multiplier
    """

    DEFAULT_HALF_LIVES: Dict[str, float] = {
        "url": 3.0,          # Phishing URLs take down fast
        "ipv4": 7.0,         # Dynamic IP allocation / cloud VPS churn
        "ipv6": 7.0,
        "domain": 21.0,      # C2 domains persist longer
        "cve": 90.0,         # Vulnerabilities remain unpatched for months
        "sha256": 180.0,     # Malware hashes are immutable artifacts
        "sha1": 180.0,
        "md5": 180.0,
    }

    FALLBACK_HALF_LIFE = 14.0

    @classmethod
    def get_recommended_half_life(cls, ioc_type: str) -> float:
        """Return default half life in days for an indicator type."""
        return cls.DEFAULT_HALF_LIVES.get(ioc_type.lower(), cls.FALLBACK_HALF_LIFE)

    @classmethod
    def calculate_effective_multiplier(cls, age_days: float, half_life_days: float) -> float:
        """Calculate decay multiplier between 0.0 and 1.0."""
        if age_days <= 0:
            return 1.0
        if half_life_days <= 0:
            return 0.0
        return float(0.5 ** (age_days / half_life_days))

    @classmethod
    def calculate_decayed_score(
        cls,
        initial_score: float,
        age_days: float,
        ioc_type: str = "ipv4",
        custom_half_life: Optional[float] = None,
        min_residual_score: float = 0.0,
    ) -> float:
        """Calculate final score after applying half-life exponential decay."""
        if initial_score <= 0:
            return 0.0

        half_life = custom_half_life if custom_half_life is not None else cls.get_recommended_half_life(ioc_type)
        multiplier = cls.calculate_effective_multiplier(age_days, half_life)
        decayed = initial_score * multiplier

        return max(min_residual_score, round(decayed, 2))
