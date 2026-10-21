"""MAC (EUI-48) and EUI-64 physical hardware address normalizer for OT/IoT telemetry."""

import re
from typing import Optional, Tuple


class MACNormalizer:
    """Validates and canonicalizes MAC / EUI-64 hardware addresses into standardized format (XX:XX:XX:XX:XX:XX)."""

    MAC_CLEAN_RE = re.compile(r"[^0-9a-fA-F]")

    @classmethod
    def normalize(cls, mac_str: str) -> Optional[Tuple[str, str]]:
        """Normalize MAC/EUI-64 address to lowercase colon-separated canonical format.

        Returns:
            Optional[Tuple[str, str]]: (canonical_mac, type: 'eui48' | 'eui64')
        """
        if not mac_str:
            return None

        hex_chars = cls.MAC_CLEAN_RE.sub("", mac_str.strip()).lower()

        if len(hex_chars) == 12:
            # Standard EUI-48 MAC
            canonical = ":".join(hex_chars[i : i + 2] for i in range(0, 12, 2))
            return canonical, "eui48"
        elif len(hex_chars) == 16:
            # Extended EUI-64
            canonical = ":".join(hex_chars[i : i + 2] for i in range(0, 16, 2))
            return canonical, "eui64"

        return None
