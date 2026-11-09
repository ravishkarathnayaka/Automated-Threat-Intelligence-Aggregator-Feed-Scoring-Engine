"""Fast-Flux DNS botnet proxy rotation and ultra-low TTL infrastructure detector."""

from typing import Iterable, List, Tuple


class FastFluxDNSDetector:
    """Identifies Single-Flux and Double-Flux botnet C2 domains via rapid IP churn and low DNS TTL."""

    @classmethod
    def evaluate_flux(
        cls,
        resolved_ips: Iterable[str],
        min_ttl_seconds: int = 300,
        unique_asns_count: int = 1,
    ) -> Tuple[bool, float, str]:
        """Evaluates DNS resolution telemetry for Fast-Flux characteristics.

        Args:
            resolved_ips: Iterable of distinct IPv4/IPv6 addresses returned for the domain.
            min_ttl_seconds: Minimum observed DNS A/AAAA record Time-To-Live in seconds.
            unique_asns_count: Number of autonomous systems spanning the resolved IPs.

        Returns:
            Tuple[bool, float, str]: (is_fast_flux, risk_penalty, classification)
        """
        ips: List[str] = list({ip.strip() for ip in resolved_ips if ip.strip()})
        ip_count = len(ips)

        # Double/High-density Fast-Flux: >= 8 distinct IPs across >= 4 ASNs with TTL <= 180s
        if ip_count >= 8 and unique_asns_count >= 4 and min_ttl_seconds <= 180:
            return True, 35.0, "high_confidence_multi_asn_fast_flux_botnet"

        # Moderate Fast-Flux: >= 5 distinct IPs across >= 3 ASNs with TTL <= 300s
        if ip_count >= 5 and unique_asns_count >= 3 and min_ttl_seconds <= 300:
            return True, 25.0, "single_flux_proxy_rotation_network"

        # Ephemeral DNS TTL evasion (< 60s with multiple IPs across different networks)
        if min_ttl_seconds < 60 and ip_count >= 3 and unique_asns_count >= 2:
            return True, 15.0, "ephemeral_ttl_dns_evasion"

        return False, 0.0, "stable_dns_hosting_profile"
