"""Autonomous System (ASN) reputation and bulletproof hosting network classifier."""

from typing import Dict, Optional, Tuple


class ASNReputationProcessor:
    """Evaluates hosting network threat risk based on Autonomous System Number (ASN) reputation."""

    # Known high-abuse hosting networks / bulletproof VPS ASNs
    BULLETPROOF_ASNS: Dict[str, Tuple[float, str]] = {
        "AS200019": (35.0, "Alexhost bulletproof hosting"),
        "AS44477": (30.0, "Stark Industries C2 hosting"),
        "AS49870": (25.0, "Alsycon bulletproof transit"),
        "AS204957": (25.0, "Green Floid offshore VPS"),
        "AS62005": (20.0, "BlueVPS offshore hosting"),
    }

    # Major trusted hyperscalers (penalties should not apply to generic cloud tenants without corroboration)
    HYPERSCALER_ASNS: Dict[str, str] = {
        "AS16509": "Amazon Web Services",
        "AS15169": "Google Cloud",
        "AS8075": "Microsoft Azure",
        "AS13335": "Cloudflare Anycast",
    }

    @classmethod
    def evaluate(cls, asn_str: Optional[str]) -> Tuple[float, str]:
        """Evaluate ASN reputation risk penalty.

        Returns:
            Tuple[float, str]: (penalty_score, classification)
        """
        if not asn_str:
            return 0.0, "unknown_asn"

        clean = asn_str.strip().upper()
        if not clean.startswith("AS"):
            clean = f"AS{clean}"

        if clean in cls.BULLETPROOF_ASNS:
            penalty, desc = cls.BULLETPROOF_ASNS[clean]
            return penalty, f"bulletproof_asn: {desc}"

        if clean in cls.HYPERSCALER_ASNS:
            return 0.0, f"hyperscaler_cloud: {cls.HYPERSCALER_ASNS[clean]}"

        return 0.0, "standard_commercial_asn"
