"""Bhattacharyya Coefficient and Hellinger Affinity for threat actor campaign attribution."""

import math
from typing import Dict, Tuple


class BhattacharyyaDistanceScorer:
    """Computes Bhattacharyya coefficient BC(P, Q) and distance D_B(P, Q) over TTP/tag profiles."""

    @classmethod
    def compute_distance(
        cls,
        profile_p: Dict[str, float],
        profile_q: Dict[str, float],
    ) -> Tuple[float, float, str]:
        """Calculates Bhattacharyya coefficient [0, 1] and distance [0, inf).

        Args:
            profile_p: First campaign TTP/feature weight mapping.
            profile_q: Second campaign TTP/feature weight mapping.

        Returns:
            Tuple[float, float, str]: (bhattacharyya_coeff, bhattacharyya_distance, attribution_match)
        """
        sum_p = sum(max(0.0, float(v)) for v in profile_p.values())
        sum_q = sum(max(0.0, float(v)) for v in profile_q.values())
        if sum_p <= 0 or sum_q <= 0:
            return 0.0, 99.9, "disjoint_or_empty_profiles"

        all_keys = set(profile_p.keys()) | set(profile_q.keys())
        bc = 0.0
        for k in all_keys:
            p_i = max(0.0, float(profile_p.get(k, 0.0))) / sum_p
            q_i = max(0.0, float(profile_q.get(k, 0.0))) / sum_q
            bc += math.sqrt(p_i * q_i)

        bc_clamped = max(0.0, min(1.0, bc))
        dist = -math.log(max(1e-9, bc_clamped))

        if bc_clamped >= 0.85:
            match = "high_confidence_same_threat_actor_cluster"
        elif bc_clamped >= 0.55:
            match = "moderate_ttp_overlap_shared_tooling"
        else:
            match = "distinct_unrelated_threat_actors"

        return round(bc_clamped, 4), round(dist, 4), match
