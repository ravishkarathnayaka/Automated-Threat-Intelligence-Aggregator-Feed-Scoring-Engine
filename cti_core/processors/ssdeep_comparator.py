"""Context Triggered Piecewise Hashing (ssdeep / fuzzy hash) validator and similarity evaluator."""

import re
from typing import Optional, Tuple


class SSDeepComparator:
    """Validates ssdeep fuzzy hashes and calculates similarity scores between polymorphic binaries."""

    SSDEEP_REGEX = re.compile(r"^(\d+):([a-zA-Z0-9/+]+):([a-zA-Z0-9/+]+)$")

    @classmethod
    def is_valid(cls, hash_str: str) -> bool:
        """Validate if string matches standard ssdeep fuzzy hash format."""
        if not hash_str:
            return False
        return bool(cls.SSDEEP_REGEX.match(hash_str.strip()))

    @classmethod
    def parse_components(cls, hash_str: str) -> Optional[Tuple[int, str, str]]:
        """Parse block size and dual base64-like hash sequences."""
        match = cls.SSDEEP_REGEX.match(hash_str.strip())
        if not match:
            return None
        block_size = int(match.group(1))
        h1 = match.group(2)
        h2 = match.group(3)
        return block_size, h1, h2

    @classmethod
    def calculate_similarity(cls, hash1: str, hash2: str) -> int:
        """Estimate similarity percentage (0-100) between two ssdeep hashes based on block size and common sub-sequences."""
        c1 = cls.parse_components(hash1)
        c2 = cls.parse_components(hash2)

        if not c1 or not c2:
            return 0

        b1, h1_a, h1_b = c1
        b2, h2_a, h2_b = c2

        # Block sizes must be equal or double/half to be comparable in CTPH
        if b1 == b2:
            match_score = cls._score_strings(h1_a, h2_a)
        elif b1 == b2 * 2:
            match_score = cls._score_strings(h1_a, h2_b)
        elif b2 == b1 * 2:
            match_score = cls._score_strings(h1_b, h2_a)
        else:
            return 0

        return match_score

    @classmethod
    def _score_strings(cls, s1: str, s2: str) -> int:
        """Longest common substring ratio approximation."""
        if s1 == s2:
            return 100
        # Check matching 7-character rolling windows
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 0
        matches = sum(1 for i, c in enumerate(s1[:len(s2)]) if s2[i] == c)
        return int((matches / max_len) * 100)
