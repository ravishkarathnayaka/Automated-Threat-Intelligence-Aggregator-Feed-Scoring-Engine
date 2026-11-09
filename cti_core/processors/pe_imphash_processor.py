"""PE Authenticode and Import Hash (ImpHash) malware family attribution analyzer."""

import re
from typing import Dict, Optional, Tuple


class PEImphashProcessor:
    """Evaluates Windows Portable Executable (PE) ImpHash and Rich Header signatures against known malware families."""

    IMPHASH_PATTERN = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)

    KNOWN_MALICIOUS_IMPHASHES: Dict[str, Tuple[float, str]] = {
        "f34d5f2d4577ed6d9ceec516c1f5a744": (35.0, "Mimikatz credential dumping utility import table"),
        "a7813224e0657b64d7f3e42559568173": (35.0, "Cobalt Strike default reflective DLL beacon loader"),
        "d24a03198e64262b0b50a7c772e21614": (30.0, "AsyncRAT / QuasarRAT .NET loader stub"),
        "1988029140219c871923847109283741": (30.0, "RedLine Stealer unpacked import signature"),
    }

    @classmethod
    def is_valid_imphash(cls, imphash: str) -> bool:
        """Validates 32-character hexadecimal MD5 import hash string."""
        if not imphash:
            return False
        return bool(cls.IMPHASH_PATTERN.match(imphash.strip()))

    @classmethod
    def evaluate(
        cls,
        imphash: Optional[str],
        is_signed: bool = True,
        signature_valid: bool = True,
    ) -> Tuple[float, str]:
        """Evaluates PE ImpHash and Authenticode signature status.

        Returns:
            Tuple[float, str]: (penalty_score, classification)
        """
        if not imphash:
            return 0.0, "missing_imphash"

        clean = imphash.strip().lower()
        if not cls.is_valid_imphash(clean):
            return 0.0, "invalid_imphash_format"

        if clean in cls.KNOWN_MALICIOUS_IMPHASHES:
            penalty, desc = cls.KNOWN_MALICIOUS_IMPHASHES[clean]
            return penalty, f"malicious_imphash: {desc}"

        if is_signed and not signature_valid:
            return 25.0, "revoked_or_tampered_authenticode_certificate"

        return 0.0, "unclassified_pe_imphash"
