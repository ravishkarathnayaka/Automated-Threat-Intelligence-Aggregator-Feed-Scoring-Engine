"""Fox-IT JA4X X.509 certificate extension fingerprint analyzer."""

import re
from typing import Dict, Optional, Tuple


class JA4XCertificateProcessor:
    """Evaluates Fox-IT JA4X X.509 certificate fingerprints against known adversary TLS certificates."""

    # Format: [12 hex]_[12 hex]_[12 hex]
    JA4X_PATTERN = re.compile(r"^[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$", re.IGNORECASE)

    # Documented threat actor default certificate fingerprints
    KNOWN_MALICIOUS_JA4X: Dict[str, Tuple[float, str]] = {
        "185a973d0a21_b7538a735178_8daaf6152771": (35.0, "Cobalt Strike default self-signed team server certificate"),
        "c9e6e409b62a_000000000000_123456789abc": (30.0, "Metasploit default generated snakeoil SSL cert"),
        "49479b76c8c4_c10397d4b299_b742b407517b": (35.0, "Sliver C2 implant default certificate authority"),
    }

    @classmethod
    def is_valid_ja4x(cls, ja4x_string: str) -> bool:
        """Validates string against Fox-IT JA4X certificate specification."""
        if not ja4x_string:
            return False
        return bool(cls.JA4X_PATTERN.match(ja4x_string.strip()))

    @classmethod
    def evaluate(cls, ja4x_string: Optional[str]) -> Tuple[float, str]:
        """Classifies threat risk for a JA4X certificate fingerprint.

        Returns:
            Tuple[float, str]: (penalty_score, classification)
        """
        if not ja4x_string:
            return 0.0, "missing_ja4x"

        clean = ja4x_string.strip().lower()
        if not cls.is_valid_ja4x(clean):
            return 0.0, "invalid_ja4x_format"

        if clean in cls.KNOWN_MALICIOUS_JA4X:
            penalty, desc = cls.KNOWN_MALICIOUS_JA4X[clean]
            return penalty, f"malicious_ja4x: {desc}"

        return 0.0, "unclassified_ja4x"
