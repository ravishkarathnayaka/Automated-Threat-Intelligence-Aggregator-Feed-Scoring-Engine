"""Fox-IT JA4S TLS server response network fingerprint analyzer."""

import re
from typing import Dict, Optional, Tuple


class JA4SFingerprintProcessor:
    """Evaluates Fox-IT JA4S TLS Server Hello fingerprints against known C2 server frameworks."""

    # Format: [t|q|d][0-9]{2}[0-9]{2}[a-z0-9]{2}_[0-9a-f]{4}_[0-9a-f]{12}
    JA4S_PATTERN = re.compile(r"^[tqd][0-9]{4}[a-z0-9]{2}_[0-9a-f]{4}_[0-9a-f]{12}$", re.IGNORECASE)

    # Documented threat framework JA4S signatures (penalty, description)
    KNOWN_MALICIOUS_JA4S: Dict[str, Tuple[float, str]] = {
        "t1302h2_1301_a56c5b992b27": (30.0, "Cobalt Strike malleable TLS server listener"),
        "t120100_c030_000000000000": (25.0, "Metasploit default TLS server reverse handler"),
        "t1304h2_1302_49479b76c8c4": (35.0, "Sliver C2 automated HTTPS daemon"),
        "t1302h1_1301_8daaf6152771": (30.0, "Havoc C2 daemon HTTPS profile"),
    }

    @classmethod
    def is_valid_ja4s(cls, ja4s_string: str) -> bool:
        """Validates string against Fox-IT JA4S specification."""
        if not ja4s_string:
            return False
        return bool(cls.JA4S_PATTERN.match(ja4s_string.strip()))

    @classmethod
    def evaluate(cls, ja4s_string: Optional[str]) -> Tuple[float, str]:
        """Classifies threat risk for a JA4S server fingerprint.

        Returns:
            Tuple[float, str]: (penalty_score, classification)
        """
        if not ja4s_string:
            return 0.0, "missing_ja4s"

        clean = ja4s_string.strip().lower()
        if not cls.is_valid_ja4s(clean):
            return 0.0, "invalid_ja4s_format"

        if clean in cls.KNOWN_MALICIOUS_JA4S:
            penalty, desc = cls.KNOWN_MALICIOUS_JA4S[clean]
            return penalty, f"malicious_ja4s: {desc}"

        return 0.0, "unclassified_ja4s"
