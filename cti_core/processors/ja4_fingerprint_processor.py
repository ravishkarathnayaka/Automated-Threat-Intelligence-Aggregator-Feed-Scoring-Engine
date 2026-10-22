"""Fox-IT JA4 TLS client network fingerprint validator and threat classifier."""

import re
from typing import Dict, Optional, Tuple


class JA4FingerprintProcessor:
    """Validates Fox-IT JA4 TLS fingerprints and identifies known adversary C2 frameworks."""

    # Format: [t|q|d][1[0-3]][d|i][0-9]{2}[0-9]{2}[h1|h2|00]_[12 hex]_[12 hex]
    JA4_PATTERN = re.compile(r"^[tqd][0-9]{2}[di][0-9]{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$", re.IGNORECASE)

    # Documented threat framework JA4 fingerprints
    KNOWN_MALICIOUS_JA4: Dict[str, Tuple[float, str]] = {
        "t13d1516h2_8daaf6152771_b7538a735178": (30.0, "Cobalt Strike default beacon TLS client"),
        "t12d080800_c9e6e409b62a_000000000000": (25.0, "Metasploit reverse_https default handler"),
        "t13d1910h2_49479b76c8c4_c10397d4b299": (25.0, "Sliver C2 automated beacon agent"),
        "t13i1516h2_8daaf6152771_b7538a735178": (35.0, "Havoc C2 daemon raw IP listener"),
    }

    @classmethod
    def is_valid_ja4(cls, ja4_string: str) -> bool:
        """Checks if a string conforms to the JA4 fingerprint specification."""
        if not ja4_string:
            return False
        return bool(cls.JA4_PATTERN.match(ja4_string.strip()))

    @classmethod
    def evaluate(cls, ja4_string: Optional[str]) -> Tuple[float, str]:
        """Classify threat risk of JA4 fingerprint.

        Returns:
            Tuple[float, str]: (penalty_score, classification)
        """
        if not ja4_string:
            return 0.0, "missing_ja4"

        clean = ja4_string.strip().lower()
        if not cls.is_valid_ja4(clean):
            return 0.0, "invalid_ja4_format"

        if clean in cls.KNOWN_MALICIOUS_JA4:
            penalty, desc = cls.KNOWN_MALICIOUS_JA4[clean]
            return penalty, f"malicious_ja4: {desc}"

        return 0.0, "unclassified_ja4"
