"""Domain Levenshtein distance typosquatting and brand impersonation evaluator."""

from typing import Dict, List, Optional, Tuple


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class DomainTyposquatEvaluator:
    """Evaluates whether a suspicious domain is a typosquat targeting major protected brands."""

    PROTECTED_BRANDS: List[str] = [
        "google", "microsoft", "apple", "paypal", "amazon",
        "netflix", "github", "chase", "bankofamerica", "coinbase",
        "binance", "facebook", "twitter", "linkedin", "wellsfargo"
    ]

    @classmethod
    def evaluate(cls, domain: str) -> Tuple[bool, float, Optional[str]]:
        """Evaluates domain against protected brands.

        Returns:
            Tuple[bool, float, Optional[str]]: (is_typosquat, risk_penalty, target_brand)
        """
        if not domain:
            return False, 0.0, None

        # Extract base label (e.g. 'googl' from 'googl.com' or 'paypaal' from 'paypaal.xyz')
        clean = domain.strip().lower()
        parts = clean.split(".")
        candidate = parts[0] if parts else clean

        # Exact match of brand is not typosquat (could be legitimate domain unless top-level domain differs)
        for brand in cls.PROTECTED_BRANDS:
            if candidate == brand:
                continue

            dist = levenshtein_distance(candidate, brand)
            # 1 edit distance away (e.g. 'microsft', 'paypaal', 'gogle')
            if dist == 1:
                return True, 35.0, brand
            # 2 edits away for longer brands (len >= 6)
            if dist == 2 and len(brand) >= 6 and abs(len(candidate) - len(brand)) <= 1:
                return True, 25.0, brand

        return False, 0.0, None
