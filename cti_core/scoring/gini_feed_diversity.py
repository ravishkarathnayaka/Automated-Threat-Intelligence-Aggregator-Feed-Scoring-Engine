"""Gini-Simpson diversity index calculator for threat feed vendor independence."""

from collections import Counter
from typing import Dict, List


class GiniFeedDiversity:
    """Calculates diversity of reporting sources to prevent echo-chamber score inflation."""

    # Threat feed category taxonomy
    FEED_CATEGORY_MAP: Dict[str, str] = {
        "abuseipdb": "crowdsourced_osint",
        "otx": "crowdsourced_osint",
        "alienvault": "crowdsourced_osint",
        "tweetfeed": "social_osint",
        "urlscan": "web_scanner",
        "virustotal": "commercial_multiscanner",
        "cisa_kev": "government_authoritative",
        "feodo": "curated_malware_lab",
        "threatfox": "curated_malware_lab",
        "urlhaus": "curated_malware_lab",
        "vxvault": "curated_malware_lab",
        "spamhaus": "reputation_authority",
        "greynoise": "internet_scanner_sensor",
        "cins_army": "honeypot_network",
        "internal_honeypot": "honeypot_network",
    }

    @classmethod
    def get_category(cls, feed_name: str) -> str:
        """Map feed identifier to its intelligence taxonomy category."""
        clean = feed_name.lower().replace("-", "_").strip()
        for key, cat in cls.FEED_CATEGORY_MAP.items():
            if key in clean:
                return cat
        return "unclassified_community"

    @classmethod
    def calculate_gini_simpson_index(cls, feed_names: List[str]) -> float:
        """Computes Gini-Simpson diversity index: D = 1 - sum(p_i^2).

        Returns:
            float in [0.0, 1.0]. High value indicates diverse multi-source evidence.
        """
        if not feed_names or len(feed_names) <= 1:
            return 0.0

        categories = [cls.get_category(f) for f in feed_names]
        total = len(categories)
        counts = Counter(categories)

        sum_sq = sum((count / total) ** 2 for count in counts.values())
        diversity = 1.0 - sum_sq
        return round(max(0.0, min(1.0, diversity)), 3)

    @classmethod
    def calculate_diversity_multiplier(cls, feed_names: List[str]) -> float:
        """Scales consensus multiplier: penalizes duplicate feeds in same category."""
        n = len(feed_names)
        if n <= 1:
            return 1.0

        diversity = cls.calculate_gini_simpson_index(feed_names)
        # Bounded between 1.0 and 1.5 based on true cross-category corroboration
        return round(1.0 + (diversity * 0.5), 2)
