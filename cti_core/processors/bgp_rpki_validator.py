"""BGP Resource Public Key Infrastructure (RPKI) Route Origin Validation (ROV) analyzer."""

import re
from typing import Dict, Optional, Tuple


class BGPRPKIValidator:
    """Evaluates BGP route announcements and origin ASNs for RPKI Route Origin Authorization (ROA) anomalies."""

    ASN_REGEX = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)

    # Known frequent hijack / bogon / unallocated ASN ranges or suspicious transit
    KNOWN_ROGUE_ASNS: Dict[int, str] = {
        200019: "Known bulletproof / frequent BGP route leak origin",
        44477: "High-risk offshore transit provider with recurrent ROA invalid prefixes",
        64512: "Private Use ASN (RFC 6996) leaked into global routing table",
        65535: "Reserved 16-bit ASN leaked into global routing table",
    }

    @classmethod
    def evaluate_roa(
        cls,
        origin_asn: str,
        rpki_status: str = "valid",
        prefix_length: int = 24,
        max_roa_length: Optional[int] = None,
    ) -> Tuple[bool, float, str]:
        """Evaluates RPKI Route Origin Validation state and prefix specificity.

        Args:
            origin_asn: Autonomous System Number announcing the prefix (e.g. 'AS200019').
            rpki_status: ROV status ('valid', 'invalid', 'not_found').
            prefix_length: Announced IPv4/IPv6 CIDR prefix length.
            max_roa_length: Maximum permitted prefix length in ROA record.

        Returns:
            Tuple[bool, float, str]: (is_hijack_risk, risk_penalty, classification)
        """
        match = cls.ASN_REGEX.match(str(origin_asn).strip())
        if not match:
            return False, 0.0, "invalid_asn_format"

        asn_num = int(match.group(1))
        status_clean = rpki_status.strip().lower()

        # RFC 6996 Private ASNs (64512-65534) or reserved 0 / 65535
        if asn_num == 0 or (64512 <= asn_num <= 65535):
            return True, 35.0, "bogon_private_asn_global_bgp_leak"

        if status_clean == "invalid":
            return True, 35.0, "rpki_roa_invalid_bgp_prefix_hijack"

        if max_roa_length is not None and prefix_length > max_roa_length:
            return True, 30.0, "rpki_subprefix_hijack_exceeds_max_length"

        if asn_num in cls.KNOWN_ROGUE_ASNS:
            return True, 25.0, f"rogue_origin_asn: {cls.KNOWN_ROGUE_ASNS[asn_num]}"

        if status_clean == "not_found" and prefix_length > 24:
            return True, 15.0, "unverified_roa_hyper_specific_prefix"

        return False, 0.0, "rpki_rov_verified_origin"
