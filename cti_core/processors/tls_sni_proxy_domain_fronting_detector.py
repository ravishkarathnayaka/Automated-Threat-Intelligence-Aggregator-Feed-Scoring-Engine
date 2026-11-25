"""TLS SNI vs HTTP Host header mismatch and CDN domain-fronting egress evasion detector."""

from typing import Optional, Tuple


class DomainFrontingDetector:
    """Detects adversary domain fronting evasion where TLS SNI differs from inner HTTP Host header."""

    CDN_PROVIDERS = (
        "cloudflare.com",
        "cloudfront.net",
        "fastly.net",
        "azureedge.net",
        "akamaiedge.net",
    )

    @classmethod
    def evaluate(
        cls,
        tls_sni: Optional[str],
        http_host: Optional[str],
    ) -> Tuple[bool, float, str]:
        """Evaluates pair for domain-fronting indicators.

        Args:
            tls_sni: Server Name Indication in TLS ClientHello.
            http_host: HTTP/1.1 or HTTP/2 :authority / Host header inside encrypted tunnel.

        Returns:
            Tuple[bool, float, str]: (is_fronting, risk_penalty, description)
        """
        if not tls_sni or not http_host:
            return False, 0.0, "missing_sni_or_host_header"

        sni_clean = tls_sni.strip().lower()
        host_clean = http_host.strip().lower().split(":")[0]

        if sni_clean == host_clean:
            return False, 0.0, "congruent_sni_and_http_host"

        # Check if SNI is a known legitimate CDN or high-reputation domain used to mask C2 Host
        is_fronted_over_cdn = any(cdn in sni_clean for cdn in cls.CDN_PROVIDERS)
        if is_fronted_over_cdn:
            return True, 35.0, f"high_confidence_cdn_domain_fronting_evasion: {sni_clean} masks {host_clean}"

        return True, 25.0, f"tls_sni_host_mismatch_anomaly: {sni_clean} != {host_clean}"
