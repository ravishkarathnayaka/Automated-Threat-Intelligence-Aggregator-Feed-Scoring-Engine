"""Kullback-Leibler and Jensen-Shannon relative entropy evaluator for feed score distribution drift."""

import math
from typing import Dict, List, Optional, Tuple


class KLDivergenceEvaluator:
    """Calculates relative entropy (KL divergence) and symmetric Jensen-Shannon divergence (JSD)

    to quantify distribution shift and concept drift across threat feeds over time.
    """

    EPSILON = 1e-9

    @classmethod
    def _normalize(cls, counts: Dict[str, float], all_keys: List[str]) -> List[float]:
        """Normalizes counts into a probability distribution with Laplace-like epsilon smoothing."""
        total = sum(counts.get(k, 0.0) for k in all_keys) + (cls.EPSILON * len(all_keys))
        return [(counts.get(k, 0.0) + cls.EPSILON) / total for k in all_keys]

    @classmethod
    def compute_kl(cls, p: List[float], q: List[float]) -> float:
        """Computes D_KL(P || Q) = sum P_i * ln(P_i / Q_i).

        Returns non-negative divergence in nats.
        """
        if len(p) != len(q):
            raise ValueError("Distributions P and Q must have identical dimensionality")

        kl = 0.0
        for p_i, q_i in zip(p, q):
            p_val = max(p_i, cls.EPSILON)
            q_val = max(q_i, cls.EPSILON)
            kl += p_val * math.log(p_val / q_val)
        return max(0.0, kl)

    @classmethod
    def compute_jsd(cls, p: List[float], q: List[float]) -> float:
        """Computes symmetric Jensen-Shannon Divergence: JSD(P || Q) = 0.5*KL(P||M) + 0.5*KL(Q||M)."""
        m = [0.5 * (p_i + q_i) for p_i, q_i in zip(p, q)]
        jsd = 0.5 * cls.compute_kl(p, m) + 0.5 * cls.compute_kl(q, m)
        return max(0.0, jsd)

    @classmethod
    def detect_drift(
        cls,
        baseline_counts: Dict[str, float],
        current_counts: Dict[str, float],
        jsd_drift_threshold: float = 0.15,
    ) -> Dict[str, object]:
        """Evaluates whether current feed telemetry has significantly drifted from baseline."""
        all_keys = sorted(set(baseline_counts.keys()).union(set(current_counts.keys())))
        if not all_keys:
            return {"is_drifted": False, "jsd": 0.0, "kl_forward": 0.0}

        p = cls._normalize(baseline_counts, all_keys)
        q = cls._normalize(current_counts, all_keys)

        kl_pq = cls.compute_kl(p, q)
        jsd = cls.compute_jsd(p, q)
        is_drifted = jsd >= jsd_drift_threshold

        return {
            "is_drifted": is_drifted,
            "jsd": round(jsd, 4),
            "kl_forward": round(kl_pq, 4),
            "drift_severity": "HIGH" if jsd > 0.30 else ("MODERATE" if is_drifted else "LOW"),
            "evaluated_categories": all_keys,
        }
