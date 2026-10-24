"""Pairwise Jaccard similarity tracker for threat feed redundancy detection."""

from typing import Dict, List, Set, Tuple


class JaccardOverlapTracker:
    """Computes pairwise Jaccard similarity across intelligence feeds to detect vendor redundancy."""

    @classmethod
    def jaccard_index(cls, set_a: Set[str], set_b: Set[str]) -> float:
        """Calculates J(A, B) = |A ∩ B| / |A ∪ B|."""
        if not set_a and not set_b:
            return 1.0
        if not set_a or not set_b:
            return 0.0

        intersection = len(set_a.intersection(set_b))
        union = len(set_a.union(set_b))
        return round(intersection / union, 4)

    @classmethod
    def evaluate_feed_overlap(
        cls,
        feed_indicators: Dict[str, List[str]],
        redundancy_threshold: float = 0.70,
    ) -> List[Tuple[str, str, float, bool]]:
        """Evaluates all pairwise combinations of feeds for redundancy.

        Returns:
            List[Tuple[feed_1, feed_2, jaccard_index, is_redundant]]
        """
        feeds = list(feed_indicators.keys())
        results: List[Tuple[str, str, float, bool]] = []

        for i in range(len(feeds)):
            for j in range(i + 1, len(feeds)):
                f1, f2 = feeds[i], feeds[j]
                s1 = set(feed_indicators[f1])
                s2 = set(feed_indicators[f2])
                j_idx = cls.jaccard_index(s1, s2)
                is_red = j_idx >= redundancy_threshold
                results.append((f1, f2, j_idx, is_red))

        results.sort(key=lambda x: x[2], reverse=True)
        return results
