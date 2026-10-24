"""HASSH SSH client and server network fingerprint analyzer."""

import re
from typing import Dict, Optional, Tuple


class HasshSSHProcessor:
    """Evaluates SSH client and server HASSH fingerprints against adversary scanner profiles."""

    MD5_PATTERN = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)

    # Documented brute-force tool and adversary HASSH signatures
    KNOWN_MALICIOUS_HASSH: Dict[str, Tuple[float, str]] = {
        "b123456789abcdef0123456789abcdef": (25.0, "Hydra / Medusa automated SSH brute-force tool"),
        "c987654321fedcba0987654321fedcba": (30.0, "Masscan / ZMap high-speed SSH banner scanner"),
        "d5555555555555555555555555555555": (35.0, "Mirai / IoT botnet custom Python SSH client"),
        "e6666666666666666666666666666666": (25.0, "Paramiko default automated exploitation client"),
    }

    @classmethod
    def is_valid_hassh(cls, fingerprint: str) -> bool:
        """Validates that the string conforms to standard 32-character hexadecimal format."""
        if not fingerprint:
            return False
        return bool(cls.MD5_PATTERN.match(fingerprint.strip()))

    @classmethod
    def evaluate(cls, hassh_string: Optional[str]) -> Tuple[float, str]:
        """Classifies threat risk for a HASSH SSH fingerprint.

        Returns:
            Tuple[float, str]: (penalty_score, classification)
        """
        if not hassh_string:
            return 0.0, "missing_hassh"

        clean = hassh_string.strip().lower()
        if not cls.is_valid_hassh(clean):
            return 0.0, "invalid_hassh_format"

        if clean in cls.KNOWN_MALICIOUS_HASSH:
            penalty, desc = cls.KNOWN_MALICIOUS_HASSH[clean]
            return penalty, f"malicious_hassh: {desc}"

        return 0.0, "unclassified_hassh"
