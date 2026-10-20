"""Country and geopolitical risk reputation scoring for IP indicators."""

from typing import Dict, Optional, Tuple


class GeoReputationProcessor:
    """Evaluates country risk weightings for indicators based on geopolitical threat intelligence."""

    HIGH_RISK_COUNTRIES: Dict[str, float] = {
        "KP": 30.0,  # North Korea (state-sponsored cyber warfare)
        "IR": 25.0,  # Iran (APT33/APT34/Charming Kitten)
        "RU": 25.0,  # Russia (APT28/APT29/Sandworm)
        "CN": 20.0,  # China (Volt Typhoon/APT41)
        "SY": 15.0,
        "BY": 15.0,
    }

    @classmethod
    def evaluate_country(cls, country_code: Optional[str]) -> Tuple[float, str]:
        """Return risk penalty points and risk level."""
        if not country_code:
            return 0.0, "unknown_country"

        code = country_code.strip().upper()
        penalty = cls.HIGH_RISK_COUNTRIES.get(code, 0.0)

        if penalty >= 25.0:
            return penalty, "critical_geopolitical_risk"
        elif penalty > 0.0:
            return penalty, "elevated_geopolitical_risk"
        return 0.0, "standard_geopolitical_risk"
