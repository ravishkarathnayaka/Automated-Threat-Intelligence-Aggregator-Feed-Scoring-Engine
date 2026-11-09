"""Fox-IT JA4H HTTP client request network fingerprint analyzer."""

import re
from typing import Dict, Optional, Tuple


class JA4HFingerprintProcessor:
    """Evaluates Fox-IT JA4H HTTP client fingerprints against known C2 beacons and exploit scanners."""

    # Format: [ge|po|pu|de|he|op][10|11|20|30][c|n][r|n][0-9]{2}[a-z0-9]{4}_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}
    JA4H_PATTERN = re.compile(
        r"^[a-z]{2}(10|11|20|30)[cn][rn][0-9]{2}[a-z0-9]{4}_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$",
        re.IGNORECASE,
    )

    KNOWN_MALICIOUS_JA4H: Dict[str, Tuple[float, str]] = {
        "ge11nn040000_8daaf6152771_000000000000_000000000000": (
            35.0,
            "Cobalt Strike default HTTP GET malleable C2 beacon",
        ),
        "po11cn06en00_a56c5b992b27_000000000000_e3b0c44298fc": (
            30.0,
            "Sliver C2 HTTP POST implant session checkin",
        ),
        "ge11nn020000_49479b76c8c4_000000000000_000000000000": (
            25.0,
            "Nuclei automated vulnerability scanner HTTP probe",
        ),
    }

    @classmethod
    def is_valid_ja4h(cls, ja4h_string: str) -> bool:
        """Validates string against Fox-IT JA4H specification."""
        if not ja4h_string:
            return False
        return bool(cls.JA4H_PATTERN.match(ja4h_string.strip()))

    @classmethod
    def evaluate(cls, ja4h_string: Optional[str]) -> Tuple[float, str]:
        """Classifies threat risk for a JA4H HTTP client fingerprint.

        Returns:
            Tuple[float, str]: (penalty_score, classification)
        """
        if not ja4h_string:
            return 0.0, "missing_ja4h"

        clean = ja4h_string.strip().lower()
        if not cls.is_valid_ja4h(clean):
            return 0.0, "invalid_ja4h_format"

        if clean in cls.KNOWN_MALICIOUS_JA4H:
            penalty, desc = cls.KNOWN_MALICIOUS_JA4H[clean]
            return penalty, f"malicious_ja4h: {desc}"

        # Heuristic: HTTP/1.1 with no cookies, no referer, and <= 3 headers
        parts = clean.split("_")
        prefix = parts[0]
        header_count = int(prefix[6:8])
        has_cookie = prefix[4] == "c"
        has_referer = prefix[5] == "r"
        if header_count <= 3 and not has_cookie and not has_referer:
            return 15.0, "suspicious_minimal_ja4h_automation_header"

        return 0.0, "unclassified_ja4h"
