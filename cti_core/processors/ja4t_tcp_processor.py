"""Fox-IT JA4T TCP SYN / SYN-ACK stack fingerprint and raw socket scanner analyzer."""

import re
from typing import Dict, Optional, Tuple


class JA4TTCPProcessor:
    """Evaluates Fox-IT JA4T TCP stack fingerprints (Window Size, TCP Options, MSS, Window Scale)."""

    # Format: <window_size>_<tcp_options>_<mss>_<window_scale> e.g. 64240_2-4-8-1-3_1460_7
    JA4T_PATTERN = re.compile(r"^[0-9]+_[0-9\-]+_[0-9]+_[0-9]+$")

    KNOWN_SCANNER_JA4T: Dict[str, Tuple[float, str]] = {
        "1024_2_1460_0": (35.0, "Masscan stateless raw TCP SYN scanner"),
        "65535_2_1460_0": (30.0, "ZMap high-speed stateless internet scanner"),
        "29200_2-4-8-1-3_1460_7": (15.0, "Automated Linux headless botnet scanner"),
    }

    @classmethod
    def is_valid_ja4t(cls, ja4t_string: str) -> bool:
        """Validates string against Fox-IT JA4T specification."""
        if not ja4t_string:
            return False
        return bool(cls.JA4T_PATTERN.match(ja4t_string.strip()))

    @classmethod
    def evaluate(cls, ja4t_string: Optional[str]) -> Tuple[float, str]:
        """Classifies threat risk for a JA4T TCP fingerprint.

        Returns:
            Tuple[float, str]: (penalty_score, classification)
        """
        if not ja4t_string:
            return 0.0, "missing_ja4t"

        clean = ja4t_string.strip()
        if not cls.is_valid_ja4t(clean):
            return 0.0, "invalid_ja4t_format"

        if clean in cls.KNOWN_SCANNER_JA4T:
            penalty, desc = cls.KNOWN_SCANNER_JA4T[clean]
            return penalty, f"malicious_ja4t: {desc}"

        parts = clean.split("_")
        win_size = int(parts[0])
        options = parts[1]
        win_scale = int(parts[3])

        # Raw socket SYN scanners typically send only MSS option ('2') with 0 window scale
        if options == "2" and win_scale == 0 and win_size <= 4096:
            return 25.0, "raw_socket_syn_scanner_signature"

        return 0.0, "normal_tcp_stack_ja4t"
