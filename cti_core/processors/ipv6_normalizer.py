"""IPv6 indicator normalization, RFC 5952 compression, and address expansion processor."""

import ipaddress
from typing import Optional, Tuple


class IPv6Normalizer:
    """Provides RFC 5952 canonicalization, hextet expansion, and IPv4-mapped translation."""

    @staticmethod
    def strip_zone_index(ip_str: str) -> str:
        """Strip link-local scope/zone ID (e.g. fe80::1%eth0 -> fe80::1)."""
        return ip_str.split("%")[0].strip()

    @staticmethod
    def compress_ipv6(ip_str: str) -> Optional[str]:
        """Convert IPv6 address to RFC 5952 canonical compressed format."""
        clean = IPv6Normalizer.strip_zone_index(ip_str)
        try:
            addr = ipaddress.IPv6Address(clean)
            return addr.compressed
        except ValueError:
            return None

    @staticmethod
    def expand_ipv6(ip_str: str) -> Optional[str]:
        """Expand IPv6 address to full 8-hextet 4-digit hexadecimal format (e.g. 2001:0db8:...)."""
        clean = IPv6Normalizer.strip_zone_index(ip_str)
        try:
            addr = ipaddress.IPv6Address(clean)
            return addr.exploded
        except ValueError:
            return None

    @staticmethod
    def is_ipv4_mapped(ip_str: str) -> Tuple[bool, Optional[str]]:
        """
        Check if address is an IPv4-mapped IPv6 address (::ffff:w.x.y.z).
        Returns (is_mapped, extracted_ipv4).
        """
        clean = IPv6Normalizer.strip_zone_index(ip_str)
        try:
            addr = ipaddress.IPv6Address(clean)
            if addr.ipv4_mapped:
                return True, str(addr.ipv4_mapped)
            return False, None
        except ValueError:
            return False, None
