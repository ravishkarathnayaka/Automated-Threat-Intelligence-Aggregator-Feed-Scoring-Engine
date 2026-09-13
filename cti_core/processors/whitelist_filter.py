"""Strict false-positive filtration against RFC 1918, critical public DNS, and top popular domains."""

import ipaddress
from typing import Optional, Set, Tuple
from urllib.parse import urlparse

# Critical Public DNS and Infrastructure
PUBLIC_DNS_RESOLVERS = {
    "1.1.1.1": "Cloudflare Public DNS Resolver",
    "1.0.0.1": "Cloudflare Public DNS Resolver Backup",
    "8.8.8.8": "Google Public DNS Primary",
    "8.8.4.4": "Google Public DNS Secondary",
    "9.9.9.9": "Quad9 Threat-Blocking Anycast DNS",
    "149.112.112.112": "Quad9 Secondary DNS",
    "208.67.222.222": "Cisco Umbrella / OpenDNS Primary",
    "208.67.220.220": "Cisco Umbrella / OpenDNS Secondary",
    "2606:4700:4700::1111": "Cloudflare IPv6 DNS",
    "2606:4700:4700::1001": "Cloudflare IPv6 DNS Secondary",
    "2001:4860:4860::8888": "Google IPv6 DNS Primary",
    "2001:4860:4860::8844": "Google IPv6 DNS Secondary",
    "2620:fe::fe": "Quad9 IPv6 DNS",
}

# Top high-traffic domains (Tranco / Alexa Top 10k core sample)
TOP_DOMAINS: Set[str] = {
    "google.com",
    "youtube.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "cloudflare.com",
    "github.com",
    "facebook.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "wikipedia.org",
    "netflix.com",
    "yahoo.com",
    "bing.com",
    "live.com",
    "office.com",
    "instagram.com",
    "adobe.com",
    "zoom.us",
    "akamai.net",
    "akamaitechnologies.com",
    "fastly.net",
    "aws.amazon.com",
    "googleapis.com",
    "gstatic.com",
    "windows.net",
    "azure.com",
    "digicert.com",
    "letsencrypt.org",
    "verisign.com",
}


class WhitelistFilter:
    """Evaluates indicators to prevent blocking critical infrastructure or benign assets."""

    @staticmethod
    def is_whitelisted(ioc_type: str, value: str) -> Tuple[bool, Optional[str]]:
        """Check if indicator matches RFC 1918, public DNS, or Alexa/Tranco top domains."""
        type_str = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type).lower()

        # 1. IP Validation
        if type_str in ("ipv4", "ipv6"):
            # Direct check against public DNS resolvers
            if value in PUBLIC_DNS_RESOLVERS:
                return True, f"Critical Public Infrastructure: {PUBLIC_DNS_RESOLVERS[value]}"

            try:
                ip_obj = ipaddress.ip_address(value)

                if ip_obj.is_private:
                    return True, f"RFC 1918 / Private IP Range: {value}"
                if ip_obj.is_loopback:
                    return True, f"Loopback Address: {value}"
                if ip_obj.is_reserved:
                    return True, f"IETF Reserved Address: {value}"
                if ip_obj.is_link_local:
                    return True, f"Link-Local Address: {value}"
                if ip_obj.is_multicast:
                    return True, f"Multicast Address: {value}"

            except ValueError:
                pass

        # 2. Domain Validation
        elif type_str == "domain":
            domain = value.lower().strip(".")
            if domain in TOP_DOMAINS:
                return True, f"Tranco/Alexa Top 10k Domain: {domain}"
            # Check subdomains (e.g. login.microsoft.com)
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                parent_candidate = ".".join(parts[i:])
                if parent_candidate in TOP_DOMAINS:
                    return True, f"Subdomain of Whitelisted Domain: {parent_candidate}"

        # 3. URL Validation
        elif type_str == "url":
            try:
                parsed = urlparse(value)
                netloc = parsed.netloc.split(":")[0].lower()
                # Check if host is whitelisted IP or domain
                ip_res, ip_reason = WhitelistFilter.is_whitelisted("ipv4", netloc)
                if ip_res:
                    return True, f"URL Host Whitelisted: {ip_reason}"
                dom_res, dom_reason = WhitelistFilter.is_whitelisted("domain", netloc)
                if dom_res:
                    return True, f"URL Host Whitelisted: {dom_reason}"
            except Exception:
                pass

        return False, None
