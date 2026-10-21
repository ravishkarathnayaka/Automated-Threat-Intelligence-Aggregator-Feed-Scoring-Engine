"""Dynamic DNS (DDNS) provider detector and apex domain flattener."""

from typing import Dict, Optional, Tuple


class SubdomainFlattener:
    """Detects Dynamic DNS (DDNS) providers and extracts apex domains and hostnames."""

    KNOWN_DDNS_PROVIDERS: set[str] = {
        "duckdns.org",
        "no-ip.com",
        "ddns.net",
        "dynu.net",
        "hopto.org",
        "zapto.org",
        "bounceme.net",
        "freeddns.org",
        "ngrok.io",
        "ngrok-free.app",
        "localtunnel.me",
    }

    @classmethod
    def analyze_domain(cls, domain: str) -> Dict[str, Optional[str | bool]]:
        """Deconstruct domain into apex, subdomain, and evaluate DDNS provider presence."""
        clean = domain.strip().lower().rstrip(".")
        parts = clean.split(".")

        if len(parts) <= 1:
            return {
                "input": domain,
                "is_ddns": False,
                "apex_domain": clean,
                "subdomain": None,
                "ddns_provider": None,
            }

        # Check DDNS suffixes
        matched_ddns = None
        for ddns in cls.KNOWN_DDNS_PROVIDERS:
            if clean.endswith(f".{ddns}"):
                matched_ddns = ddns
                break

        if matched_ddns:
            sub = clean[: -(len(matched_ddns) + 1)]
            return {
                "input": domain,
                "is_ddns": True,
                "apex_domain": matched_ddns,
                "subdomain": sub,
                "ddns_provider": matched_ddns,
            }

        apex = ".".join(parts[-2:])
        sub = ".".join(parts[:-2]) if len(parts) > 2 else None

        return {
            "input": domain,
            "is_ddns": False,
            "apex_domain": apex,
            "subdomain": sub,
            "ddns_provider": None,
        }
