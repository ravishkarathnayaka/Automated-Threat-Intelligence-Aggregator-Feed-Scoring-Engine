"""IPv6 modified EUI-64 hardware MAC address extractor for SLAAC hosts."""

import ipaddress
import re
from typing import Optional, Tuple


class IPv6EUI64Extractor:
    """Extracts embedded physical MAC address from IPv6 SLAAC modified EUI-64 interface identifiers."""

    @classmethod
    def extract_mac(cls, ipv6_str: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Analyzes an IPv6 address to detect and extract modified EUI-64 embedded MAC.

        Returns:
            Tuple[bool, Optional[str], Optional[str]]: (has_eui64, mac_address, vendor_oui)
        """
        if not ipv6_str:
            return False, None, None

        try:
            ip = ipaddress.IPv6Address(ipv6_str.strip())
        except ValueError:
            return False, None, None

        # Check if the interface identifier has 0xff, 0xfe in bytes 11 and 12 (0-indexed from 16 bytes)
        raw_bytes = ip.packed
        if raw_bytes[11] != 0xFF or raw_bytes[12] != 0xFE:
            return False, None, None

        # Extract MAC: byte 8 (with bit 1 inverted), byte 9, byte 10, byte 13, byte 14, byte 15
        b0 = raw_bytes[8] ^ 0x02  # Invert universal/local bit
        b1 = raw_bytes[9]
        b2 = raw_bytes[10]
        b3 = raw_bytes[13]
        b4 = raw_bytes[14]
        b5 = raw_bytes[15]

        mac = f"{b0:02x}:{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}".upper()
        oui = f"{b0:02x}:{b1:02x}:{b2:02x}".upper()
        return True, mac, oui
