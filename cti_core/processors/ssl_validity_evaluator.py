"""X.509 certificate validity lifespan anomaly evaluator."""

from typing import Tuple


class SSLCertificateValidityEvaluator:
    """Evaluates certificate valid_from to valid_to duration for lifespan anomalies."""

    MAX_LEGITIMATE_LIFESPAN_DAYS = 398  # CA/B Forum standard
    SUSPICIOUS_LONG_LIFESPAN_DAYS = 3650  # 10 years default self-signed
    DISPOSABLE_SHORT_LIFESPAN_DAYS = 3  # Ephemeral disposable cert

    @classmethod
    def evaluate_lifespan(cls, validity_days: float) -> Tuple[bool, float, str]:
        """Evaluates certificate lifespan in days.

        Returns:
            Tuple[bool, float, str]: (is_anomalous, risk_penalty, explanation)
        """
        if validity_days <= 0:
            return True, 25.0, "expired_or_invalid_zero_day_validity"

        if validity_days >= cls.SUSPICIOUS_LONG_LIFESPAN_DAYS:
            return True, 30.0, f"abnormally_long_self_signed_lifespan ({int(validity_days)} days >= 10 years)"
        elif validity_days > 825:
            return True, 15.0, f"deprecated_extended_lifespan ({int(validity_days)} days > 825 days)"
        elif validity_days <= cls.DISPOSABLE_SHORT_LIFESPAN_DAYS:
            return True, 25.0, f"disposable_ephemeral_campaign_certificate ({round(validity_days, 1)} days)"

        return False, 0.0, "standard_cab_forum_validity"
