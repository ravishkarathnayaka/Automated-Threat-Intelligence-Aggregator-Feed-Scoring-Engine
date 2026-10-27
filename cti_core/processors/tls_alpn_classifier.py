"""TLS Application-Layer Protocol Negotiation (ALPN) anomaly classifier."""

from typing import List, Optional, Tuple


class TLSALPNClassifier:
    """Evaluates TLS ALPN protocol negotiation strings for covert channels and C2 evasion."""

    STANDARD_PRODUCTION_ALPNS = {"h2", "http/1.1", "h3"}

    # Suspicious or covert tunneling ALPNs
    COVERT_ALPNS = {
        "c2": (35.0, "Adversary custom C2 protocol ALPN"),
        "spdy/3": (25.0, "Deprecated SPDY protocol in modern TLS session"),
        "xmpp-client": (20.0, "XMPP chat protocol tunnel on HTTPS port 443"),
        "dot": (20.0, "DNS-over-TLS protocol negotiation"),
        "tunnel": (30.0, "Generic covert TCP tunnel ALPN"),
    }

    @classmethod
    def evaluate(cls, alpn_list: Optional[List[str]]) -> Tuple[bool, float, str]:
        """Evaluates negotiated or offered ALPN protocols.

        Returns:
            Tuple[bool, float, str]: (is_suspicious, risk_penalty, classification)
        """
        if not alpn_list:
            # Modern web browsers almost always offer ALPN (h2, http/1.1). Missing ALPN in automated tools is a minor signal.
            return True, 10.0, "missing_tls_alpn_extension"

        clean_alpns = [a.strip().lower() for a in alpn_list if a.strip()]

        for a in clean_alpns:
            if a in cls.COVERT_ALPNS:
                penalty, desc = cls.COVERT_ALPNS[a]
                return True, penalty, desc

        # Check if contains any standard web protocol
        has_standard = any(a in cls.STANDARD_PRODUCTION_ALPNS for a in clean_alpns)
        if not has_standard:
            return True, 20.0, "non_standard_proprietary_alpn_protocols"

        return False, 0.0, "standard_web_alpn"
