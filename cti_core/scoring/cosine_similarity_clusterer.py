"""Vector cosine similarity evaluator for indicator clustering and campaign attribution."""

import math
from typing import Any, Dict, List, Set, Tuple


class CosineSimilarityClusterer:
    """Computes cosine similarity between indicator feature vectors (tags, malware families, tactics)."""

    @classmethod
    def similarity(cls, tags_a: List[str], tags_b: List[str]) -> float:
        """Computes cosine similarity between two multi-hot categorical tag lists."""
        if not tags_a or not tags_b:
            return 0.0

        set_a = {t.lower().strip() for t in tags_a if t.strip()}
        set_b = {t.lower().strip() for t in tags_b if t.strip()}

        if not set_a or not set_b:
            return 0.0

        # Dot product is the count of shared tags
        intersection = len(set_a.intersection(set_b))
        magnitude_a = math.sqrt(len(set_a))
        magnitude_b = math.sqrt(len(set_b))

        sim = intersection / (magnitude_a * magnitude_b)
        return round(sim, 4)

    @classmethod
    def find_affiliated_indicators(
        cls,
        target_tags: List[str],
        candidate_pool: List[Dict[str, Any]],
        threshold: float = 0.5,
    ) -> List[Tuple[str, float]]:
        """Returns candidate indicators exceeding cosine similarity threshold."""
        matches: List[Tuple[str, float]] = []
        for cand in candidate_pool:
            c_val = cand.get("normalized_value") or cand.get("value", "")
            c_tags = cand.get("tags", [])
            sim = cls.similarity(target_tags, c_tags)
            if sim >= threshold:
                matches.append((c_val, sim))

        matches.sort(key=lambda x: x[1], reverse=True)
        return matches
