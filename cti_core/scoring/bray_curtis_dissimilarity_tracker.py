"""Bray-Curtis ecological dissimilarity tracker for threat feed portfolio distinctiveness."""

from typing import Dict, List, Tuple


class BrayCurtisDissimilarityTracker:
    """Calculates Bray-Curtis dissimilarity between threat feeds based on category or indicator count distributions.

    Quantifies feed portfolio overlap and individual feed uniqueness to eliminate redundant vendor subscriptions.
    """

    @staticmethod
    def calculate_dissimilarity(
        counts_a: Dict[str, float], counts_b: Dict[str, float]
    ) -> float:
        """Calculates Bray-Curtis dissimilarity BC = sum(|u_i - v_i|) / sum(u_i + v_i).

        Returns:
            float: Value in [0.0, 1.0], where 0.0 is identical and 1.0 is completely disjoint.
        """
        all_keys = set(counts_a.keys()).union(set(counts_b.keys()))
        diff_sum = 0.0
        total_sum = 0.0

        for k in all_keys:
            u_i = counts_a.get(k, 0.0)
            v_i = counts_b.get(k, 0.0)
            diff_sum += abs(u_i - v_i)
            total_sum += u_i + v_i

        if total_sum == 0.0:
            return 0.0

        return round(diff_sum / total_sum, 4)

    @classmethod
    def evaluate_portfolio(
        cls, feeds: Dict[str, Dict[str, float]]
    ) -> Dict[str, object]:
        """Calculates pairwise dissimilarities and average portfolio uniqueness score."""
        feed_names = list(feeds.keys())
        n = len(feed_names)
        if n < 2:
            return {
                "pairwise_dissimilarity": {},
                "average_uniqueness": 1.0 if n == 1 else 0.0,
                "feed_uniqueness_ranking": {k: 1.0 for k in feed_names},
            }

        pairwise: Dict[str, float] = {}
        feed_totals: Dict[str, float] = {k: 0.0 for k in feed_names}
        pair_count = 0

        for i in range(n):
            for j in range(i + 1, n):
                f1, f2 = feed_names[i], feed_names[j]
                bc = cls.calculate_dissimilarity(feeds[f1], feeds[f2])
                key = f"{f1}__vs__{f2}"
                pairwise[key] = bc
                feed_totals[f1] += bc
                feed_totals[f2] += bc
                pair_count += 1

        avg_uniqueness = sum(pairwise.values()) / pair_count if pair_count > 0 else 0.0
        rankings = {
            k: round(feed_totals[k] / (n - 1), 4) for k in feed_names
        }

        return {
            "pairwise_dissimilarity": pairwise,
            "average_portfolio_uniqueness": round(avg_uniqueness, 4),
            "feed_uniqueness_ranking": dict(
                sorted(rankings.items(), key=lambda x: x[1], reverse=True)
            ),
        }
