"""DNS over HTTPS (DoH) and DNS over TLS (DoT) egress evasion detector."""

from typing import Dict, List, Optional, Tuple


class DNSOverHTTPSDetector:
    """Detects communication to known and suspicious public and custom DNS-over-HTTPS/TLS endpoints."""

    # Well-known public DoH/DoT provider endpoints
    PUBLIC_DOH_ENDPOINTS: Dict[str, Tuple[float, str]] = {
        "cloudflare-dns.com": (15.0, "Cloudflare 1.1.1.1 DoH (Evasion of local corporate DNS)"),
        "dns.google": (15.0, "Google Public DoH (Evasion of local corporate DNS)"),
        "dns.quad9.net": (15.0, "Quad9 DoH resolver"),
        "dns.nextdns.io": (20.0, "NextDNS custom tenant DoH endpoint"),
        "doh.cleanbrowsing.org": (15.0, "CleanBrowsing DoH resolver"),
        "doh.mullvad.net": (25.0, "Mullvad VPN anonymized DoH resolver"),
    }

    # High-risk public DoH IP addresses
    DOH_IPS: Dict[str, Tuple[float, str]] = {
        "1.1.1.1": (15.0, "Cloudflare DoH IP"),
        "1.0.0.1": (15.0, "Cloudflare DoH IP"),
        "8.8.8.8": (15.0, "Google DoH IP"),
        "8.8.4.4": (15.0, "Google DoH IP"),
        "9.9.9.9": (15.0, "Quad9 DoH IP"),
        "149.112.112.112": (15.0, "Quad9 DoH IP"),
        "45.90.28.0": (20.0, "NextDNS DoH IP"),
    }

    @classmethod
    def evaluate(cls, indicator: str, ioc_type: str = "domain") -> Tuple[bool, float, str]:
        """Evaluates whether an indicator is a DoH evasion endpoint.

        Returns:
            Tuple[bool, float, str]: (is_doh, risk_penalty, explanation)
        """
        if not indicator:
            return False, 0.0, "empty_indicator"

        clean = indicator.strip().lower()
        if ioc_type == "domain":
            for doh_dom, (penalty, desc) in cls.PUBLIC_DOH_ENDPOINTS.items():
                if clean == doh_dom or clean.endswith(f".{doh_dom}"):
                    return True, penalty, desc
        elif ioc_type in ("ipv4", "ipv6"):
            if clean in cls.DOH_IPS:
                penalty, desc = cls.DOH_IPS[clean]
                return True, penalty, desc

        return False, 0.0, "standard_endpoint"
