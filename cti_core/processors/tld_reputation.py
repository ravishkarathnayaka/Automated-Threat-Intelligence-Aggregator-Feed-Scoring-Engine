"""Top-level domain (TLD) risk assessment processor."""

from typing import Dict, Tuple


class TLDReputationProcessor:
    """Evaluates domain risk based on high-abuse TLD classification and suspicious TLD penalty weights."""

    # High-abuse TLDs frequently weaponized in phishing and disposable malware campaigns
    SUSPICIOUS_TLDS: Dict[str, float] = {
        "top": 25.0,
        "xyz": 20.0,
        "cc": 15.0,
        "tk": 30.0,
        "ml": 25.0,
        "ga": 25.0,
        "cf": 25.0,
        "gq": 25.0,
        "work": 20.0,
        "date": 25.0,
        "racing": 25.0,
        "click": 20.0,
        "loan": 25.0,
        "men": 25.0,
        "buzz": 20.0,
    }

    # Highly trusted infrastructure / government / education TLDs
    TRUSTED_TLDS = {"gov", "mil", "edu", "int"}

    @classmethod
    def extract_tld(cls, domain: str) -> str:
        """Extract the effective top-level domain from a domain string."""
        clean = domain.strip().lower().rstrip(".")
        parts = clean.split(".")
        return parts[-1] if len(parts) > 1 else ""

    @classmethod
    def evaluate(cls, domain: str) -> Tuple[float, str]:
        """Evaluate TLD penalty score and descriptive risk classification.

        Returns:
            Tuple[float, str]: (penalty_score, risk_level)
        """
        tld = cls.extract_tld(domain)
        if not tld:
            return 0.0, "unknown"

        if tld in cls.TRUSTED_TLDS:
            return -10.0, "trusted_infrastructure"

        penalty = cls.SUSPICIOUS_TLDS.get(tld, 0.0)
        if penalty >= 25.0:
            return penalty, "high_risk_tld"
        elif penalty > 0.0:
            return penalty, "suspicious_tld"
        return 0.0, "standard_tld"
