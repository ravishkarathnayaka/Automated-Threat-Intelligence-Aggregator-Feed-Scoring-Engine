"""Punycode normalizer and Internationalized Domain Name (IDN) homograph attack detector."""

import unicodedata
from typing import Optional, Set, Tuple


class PunycodeProcessor:
    """Handles IDN Punycode encoding, decoding, and script mixing homograph detection."""

    @staticmethod
    def to_punycode(domain: str) -> str:
        """Encode a Unicode domain name to ASCII Punycode representation (e.g. xn--...)."""
        clean_domain = domain.strip().lower().rstrip(".")
        try:
            return clean_domain.encode("idna").decode("ascii")
        except UnicodeError:
            return clean_domain

    @staticmethod
    def to_unicode(punycode_domain: str) -> str:
        """Decode an ASCII Punycode domain to readable Unicode format."""
        clean_domain = punycode_domain.strip().lower().rstrip(".")
        try:
            return clean_domain.encode("ascii").decode("idna")
        except UnicodeError:
            return clean_domain

    @staticmethod
    def detect_homograph(domain: str) -> Tuple[bool, Optional[str]]:
        """
        Detect mixed-script homograph spoofing (e.g., mixing Cyrillic/Greek with Latin).
        Returns (is_homograph, explanation).
        """
        clean_domain = domain.strip().lower().rstrip(".")
        # If it's already punycode, decode to inspect the underlying Unicode characters
        if "xn--" in clean_domain:
            try:
                clean_domain = PunycodeProcessor.to_unicode(clean_domain)
            except Exception:
                pass

        scripts_found: Set[str] = set()
        suspicious_chars: Set[str] = set()

        for char in clean_domain:
            if char in (".", "-", "_") or char.isdigit():
                continue
            name = unicodedata.name(char, "")
            script = name.split()[0] if name else "UNKNOWN"

            if script in ("CYRILLIC", "GREEK", "HEBREW", "ARABIC", "LATIN"):
                scripts_found.add(script)
                if script in ("CYRILLIC", "GREEK"):
                    suspicious_chars.add(f"{char} ({script})")

        # If domain mixes Latin with Cyrillic or Greek, it's a homograph spoofing attempt
        if "LATIN" in scripts_found and len(scripts_found) > 1:
            return True, f"Mixed Script Homograph Attack: {', '.join(scripts_found)} [{', '.join(suspicious_chars)}]"

        # If it's all Cyrillic but mimicking a standard TLD like .com
        if len(scripts_found) == 1 and "CYRILLIC" in scripts_found:
            return True, "Whole Script Confusable (Cyrillic Spoof)"

        return False, None
