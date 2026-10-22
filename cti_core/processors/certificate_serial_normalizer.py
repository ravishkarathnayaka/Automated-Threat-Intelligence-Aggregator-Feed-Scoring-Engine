"""X.509 TLS certificate serial number and thumbprint normalizer."""

import re
from typing import Optional


class CertificateSerialNormalizer:
    """Normalizes cryptographic X.509 certificate serial numbers into canonical lowercase hex format."""

    @classmethod
    def normalize_serial(cls, raw_serial: Optional[str]) -> Optional[str]:
        """Convert any valid hex or decimal serial into continuous lowercase hex.

        Returns:
            Normalized hex string without colons or spaces, or None if invalid.
        """
        if not raw_serial:
            return None

        clean = raw_serial.strip().replace(":", "").replace(" ", "").replace("-", "")

        # Check if already a valid hex string
        if re.fullmatch(r"^[0-9a-fA-F]+$", clean):
            # Strip single leading zero if uneven length
            if len(clean) % 2 != 0:
                clean = "0" + clean
            return clean.lower()

        # If decimal integer string
        if clean.isdigit():
            val = int(clean)
            hex_val = hex(val)[2:]
            if len(hex_val) % 2 != 0:
                hex_val = "0" + hex_val
            return hex_val.lower()

        return None

    @classmethod
    def format_colon_hex(cls, normalized_hex: str) -> str:
        """Formats continuous hex into standard colon-delimited presentation (e.g. 04:a1:b2)."""
        if not normalized_hex:
            return ""
        return ":".join(normalized_hex[i : i + 2] for i in range(0, len(normalized_hex), 2))
