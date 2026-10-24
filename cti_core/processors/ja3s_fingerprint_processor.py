"""JA3S TLS Server Hello network fingerprint classifier."""

import re
from typing import Dict, Optional, Tuple


class JA3SFingerprintProcessor:
    """Evaluates TLS Server Hello (JA3S) cryptographic fingerprints against known C2 profiles."""

    MD5_PATTERN = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)

    # Documented C2 Server JA3S Signatures (penalty, description)
    KNOWN_C2_JA3S: Dict[str, Tuple[float, str]] = {
        "fd4bc6036cb6b517d7455d320d57aec3": (30.0, "Cobalt Strike team server default TLS response"),
        "e35df3e00ca4ef31d42b34bebaa2f86e": (35.0, "Metasploit / Meterpreter reverse_https listener"),
        "b742b407517bac9364a42888b13e4d20": (30.0, "Sliver C2 HTTPS implant listener"),
        "0cce74b019cdf393d250e371d73a6a9b": (25.0, "PoshC2 default web server profile"),
    }

    @classmethod
    def is_valid_ja3s(cls, fingerprint: str) -> bool:
        """Validates that the string is a valid 32-character hexadecimal MD5 hash."""
        if not fingerprint:
            return False
        return bool(cls.MD5_PATTERN.match(fingerprint.strip()))

    @classmethod
    def evaluate(cls, ja3s_string: Optional[str]) -> Tuple[float, str]:
        """Classifies threat risk for a JA3S fingerprint.

        Returns:
            Tuple[float, str]: (penalty_score, classification)
        """
        if not ja3s_string:
            return 0.0, "missing_ja3s"

        clean = ja3s_string.strip().lower()
        if not cls.is_valid_ja3s(clean):
            return 0.0, "invalid_ja3s_format"

        if clean in cls.KNOWN_C2_JA3S:
            penalty, desc = cls.KNOWN_C2_JA3S[clean]
            return penalty, f"malicious_ja3s: {desc}"

        return 0.0, "unclassified_ja3s"
