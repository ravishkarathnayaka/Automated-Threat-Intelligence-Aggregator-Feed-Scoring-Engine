"""Weibull distribution hazard rate and survival model for threat infrastructure."""

import math
from typing import Dict, Tuple


class WeibullReliabilityModel:
    """Models indicator survival and hazard rate using the 2-parameter Weibull distribution.

    Reliability: R(t) = exp( - (t / scale) ^ shape )
    Hazard rate: h(t) = (shape / scale) * (t / scale) ^ (shape - 1)
    """

    # Default parameters per IoC type: (scale_days, shape_k)
    IOC_WEIBULL_PARAMS: Dict[str, Tuple[float, float]] = {
        "url": (2.5, 0.75),      # Phishing URLs die fast early (infant mortality)
        "ipv4": (8.0, 1.20),     # Malicious IPs wear out gradually as defenders block
        "ipv6": (8.0, 1.20),
        "domain": (25.0, 1.35),  # C2 domains persist then get revoked by registry
        "sha256": (180.0, 0.95), # Malware hashes maintain very stable threat lifetime
    }

    @classmethod
    def survival_probability(cls, age_days: float, ioc_type: str = "ipv4") -> float:
        """Returns survival probability R(t) in [0.0, 1.0]."""
        if age_days <= 0.0:
            return 1.0

        scale, shape = cls.IOC_WEIBULL_PARAMS.get(ioc_type.lower(), (14.0, 1.0))
        z = age_days / scale
        exponent = math.pow(z, shape)
        if exponent > 50:
            return 0.0
        return math.exp(-exponent)

    @classmethod
    def calculate_weibull_decayed_score(
        cls,
        initial_score: float,
        age_days: float,
        ioc_type: str = "ipv4",
        floor: float = 0.0,
    ) -> float:
        """Calculates decayed score under Weibull survival curve."""
        if initial_score <= 0.0:
            return 0.0
        survival = cls.survival_probability(age_days, ioc_type=ioc_type)
        decayed = initial_score * survival
        return round(max(floor, decayed), 2)
