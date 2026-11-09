"""Dempster-Shafer Evidence Theory (Belief & Plausibility) multi-feed fusion scorer."""

from typing import Dict, Iterable, Tuple


class DempsterShaferScorer:
    """Fuses uncertain threat feed assertions using Dempster's Rule of Combination.

    Frame of discernment Theta = {malicious (M), benign (B), uncertain (U = {M, B})}.
    """

    @classmethod
    def combine_masses(
        cls,
        m1: Dict[str, float],
        m2: Dict[str, float],
    ) -> Tuple[Dict[str, float], float]:
        """Combines two Basic Probability Assignments (BPAs) m1 and m2.

        Keys in m1, m2: 'malicious', 'benign', 'uncertain' summing to 1.0.

        Returns:
            Tuple[Dict[str, float], float]: (combined_bpa, conflict_factor_K)
        """
        m1_m = float(m1.get("malicious", 0.0))
        m1_b = float(m1.get("benign", 0.0))
        m1_u = max(0.0, 1.0 - m1_m - m1_b)

        m2_m = float(m2.get("malicious", 0.0))
        m2_b = float(m2.get("benign", 0.0))
        m2_u = max(0.0, 1.0 - m2_m - m2_b)

        # Conflict mass K where M intersects B = empty set
        conflict_k = (m1_m * m2_b) + (m1_b * m2_m)
        if conflict_k >= 0.9999:
            return {"malicious": 0.5, "benign": 0.5, "uncertain": 0.0}, round(conflict_k, 4)

        norm = 1.0 / (1.0 - conflict_k)

        comb_m = norm * ((m1_m * m2_m) + (m1_m * m2_u) + (m1_u * m2_m))
        comb_b = norm * ((m1_b * m2_b) + (m1_b * m2_u) + (m1_u * m2_b))
        comb_u = norm * (m1_u * m2_u)

        return (
            {
                "malicious": round(comb_m, 4),
                "benign": round(comb_b, 4),
                "uncertain": round(comb_u, 4),
            },
            round(conflict_k, 4),
        )

    @classmethod
    def fuse_evidence(
        cls,
        masses_list: Iterable[Dict[str, float]],
    ) -> Dict[str, float]:
        """Sequentially fuses an iterable of evidence mass dictionaries.

        Returns:
            Dict containing belief_malicious, plausibility_malicious, uncertainty_interval,
            conflict_k, and composite_score (0-100).
        """
        items = list(masses_list)
        if not items:
            return {
                "belief_malicious": 0.0,
                "plausibility_malicious": 1.0,
                "uncertainty_interval": 1.0,
                "conflict_k": 0.0,
                "composite_score": 50.0,
            }

        current = {
            "malicious": float(items[0].get("malicious", 0.0)),
            "benign": float(items[0].get("benign", 0.0)),
            "uncertain": max(
                0.0,
                1.0 - float(items[0].get("malicious", 0.0)) - float(items[0].get("benign", 0.0)),
            ),
        }
        max_conflict = 0.0

        for nxt in items[1:]:
            current, k = cls.combine_masses(current, nxt)
            max_conflict = max(max_conflict, k)

        bel_m = current["malicious"]
        pl_m = round(min(1.0, current["malicious"] + current["uncertain"]), 4)
        interval = round(pl_m - bel_m, 4)
        # Pignistic probability BetP(M) = Bel(M) + 0.5 * m(U)
        pignistic = bel_m + (0.5 * current["uncertain"])

        return {
            "belief_malicious": round(bel_m, 4),
            "plausibility_malicious": pl_m,
            "uncertainty_interval": interval,
            "conflict_k": round(max_conflict, 4),
            "composite_score": round(pignistic * 100.0, 2),
        }
