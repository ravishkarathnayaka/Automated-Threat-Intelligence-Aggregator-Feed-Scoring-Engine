"""JA3 and JA4 TLS client fingerprint validator and classification processor."""

import re
from typing import Optional, Tuple


class TLSFingerprintValidator:
    """Validates and classifies JA3 (MD5 hex) and JA4 (structured TLS fingerprint) signatures."""

    JA3_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
    JA4_REGEX = re.compile(r"^[tqd][0-9]{2}[di][0-9]{2}[0-9]{2}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$")

    # Known malicious JA3 fingerprints (Cobalt Strike, TrickBot, Emotet)
    MALICIOUS_JA3: dict[str, str] = {
        "72a589da586844d7f0818ce684948eea": "Cobalt Strike malleable C2 profile",
        "a0e9f5d64349fb13191bc781f81f42e1": "Metasploit default HTTPS payload",
        "6734f37431670b3ab4292b8f60f29984": "Emotet banking trojan loader",
        "51c64c77e60f3980eea90869b68c58a8": "Qakbot botnet TLS handshake",
    }

    @classmethod
    def identify_type(cls, fingerprint: str) -> Optional[str]:
        """Determine if fingerprint is JA3, JA4, or invalid."""
        fp = fingerprint.strip()
        if cls.JA3_REGEX.match(fp):
            return "ja3"
        elif cls.JA4_REGEX.match(fp.lower()):
            return "ja4"
        return None

    @classmethod
    def evaluate(cls, fingerprint: str) -> Tuple[bool, Optional[str]]:
        """Evaluate if fingerprint is known malicious.

        Returns:
            Tuple[bool, Optional[str]]: (is_malicious, threat_name)
        """
        fp = fingerprint.strip().lower()
        if fp in cls.MALICIOUS_JA3:
            return True, cls.MALICIOUS_JA3[fp]
        return False, None
