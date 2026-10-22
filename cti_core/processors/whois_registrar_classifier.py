"""Domain registrar reputation and WHOIS privacy guard risk classifier."""

from typing import Dict, Optional, Tuple


class RegistrarClassifier:
    """Classifies domain registrar threat risk and identifies privacy-shielded offshore registrars."""

    # Registrars with documented high abuse / fast-flux ratios
    HIGH_RISK_REGISTRARS: Dict[str, Tuple[float, str]] = {
        "namesilo": (15.0, "High abuse ratio / bulk discount C2 registrar"),
        "tucows": (10.0, "Common privacy-shielded phishing registrar"),
        "reg.ru": (20.0, "Frequent Russian bulletproof host registrar"),
        "epik": (25.0, "High-tolerance / offshore privacy registrar"),
        "panama privacy": (20.0, "Offshore WHOIS proxy protection service"),
        "withheldforprivacy": (15.0, "Aggressive anonymous WHOIS masking"),
    }

    # Enterprise corporate registrars (unlikely to host throwaway malware domains)
    ENTERPRISE_REGISTRARS: Dict[str, str] = {
        "markmonitor": "Enterprise brand protection registrar",
        "csc corporate": "Corporate domain management registrar",
        "safenames": "Enterprise corporate security registrar",
        "amazon": "AWS Route 53 corporate domains",
    }

    @classmethod
    def evaluate(cls, registrar_name: Optional[str]) -> Tuple[float, str]:
        """Evaluates registrar threat risk.

        Returns:
            Tuple[float, str]: (penalty_score, verdict)
        """
        if not registrar_name:
            return 0.0, "unknown_registrar"

        clean = registrar_name.lower().strip()

        for key, (penalty, desc) in cls.HIGH_RISK_REGISTRARS.items():
            if key in clean:
                return penalty, f"high_risk_registrar: {desc}"

        for key, desc in cls.ENTERPRISE_REGISTRARS.items():
            if key in clean:
                return -10.0, f"enterprise_trusted_registrar: {desc}"

        return 0.0, "standard_commercial_registrar"
