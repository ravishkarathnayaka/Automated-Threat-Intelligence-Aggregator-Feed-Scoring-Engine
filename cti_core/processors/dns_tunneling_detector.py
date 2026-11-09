"""DNS tunneling exfiltration and high-entropy subdomain payload analyzer."""

import math
from collections import Counter
from typing import Optional, Tuple


class DNSTunnelingDetector:
    """Detects iodine, dnscat2, and Cobalt Strike DNS covert channels via subdomain length and entropy."""

    @classmethod
    def calculate_entropy(cls, text: str) -> float:
        """Computes Shannon character entropy in bits per character."""
        if not text:
            return 0.0
        counts = Counter(text.lower())
        length = len(text)
        entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
        return round(entropy, 4)

    @classmethod
    def evaluate_query(cls, fqdn: Optional[str]) -> Tuple[bool, float, str]:
        """Evaluates an FQDN query for DNS tunneling exfiltration patterns.

        Returns:
            Tuple[bool, float, str]: (is_tunneling, risk_penalty, classification)
        """
        if not fqdn or "." not in fqdn:
            return False, 0.0, "invalid_or_empty_fqdn"

        clean = fqdn.strip().strip(".").lower()
        labels = clean.split(".")
        if len(labels) <= 2:
            return False, 0.0, "standard_second_level_domain"

        # Extract subdomain prefix excluding base domain + TLD
        subdomain_payload = "".join(labels[:-2])
        payload_len = len(subdomain_payload)
        entropy = cls.calculate_entropy(subdomain_payload)

        # Hex/Base32/Base64 encoded DNS payloads typically exceed 35 chars with high entropy
        if payload_len >= 48 and entropy >= 3.7:
            return True, 35.0, "high_confidence_dns_tunneling_exfiltration"
        if payload_len >= 28 and entropy >= 3.85:
            return True, 25.0, "suspicious_encoded_dns_c2_beacon_subdomain"
        if len(labels) >= 6 and payload_len >= 30:
            return True, 20.0, "excessive_label_depth_dns_covert_channel"

        return False, 0.0, "benign_subdomain_hierarchy"
