"""Markov Decision Process (MDP) for automated incident response and mitigation policy optimization."""

from typing import Dict, List, Tuple


class ThreatMitigationMDP:
    """Computes optimal automated mitigation policy given threat confidence and false positive penalty."""

    ACTIONS = ("ALLOW", "ALERT", "TARPIT", "QUARANTINE", "BLOCK_IMMEDIATE")

    # State: confidence range e.g. 'LOW' (0-39), 'MEDIUM' (40-69), 'HIGH' (70-84), 'CRITICAL' (85-100)
    # Action cost = false_positive_disruption + breach_cost_unmitigated
    @classmethod
    def evaluate_optimal_action(
        cls,
        confidence_score: float,
        business_impact_weight: float = 1.0,
    ) -> Dict[str, object]:
        """Calculates expected utility for each candidate mitigation action.

        Returns:
            Dict containing recommended_action, utility_scores, explanation.
        """
        score = max(0.0, min(100.0, float(confidence_score)))
        p_malicious = score / 100.0
        p_benign = 1.0 - p_malicious

        # Reward utilities: R(action | malicious) vs Cost(action | benign)
        # Cost of false positive (blocking legitimate user) scaled by business_impact_weight
        fp_cost = 50.0 * business_impact_weight
        breach_cost = 100.0

        utilities = {
            "ALLOW": round((-breach_cost * p_malicious), 2),
            "ALERT": round((20.0 * p_malicious) - (5.0 * p_benign), 2),
            "TARPIT": round((50.0 * p_malicious) - (15.0 * p_benign * business_impact_weight), 2),
            "QUARANTINE": round((75.0 * p_malicious) - (35.0 * p_benign * business_impact_weight), 2),
            "BLOCK_IMMEDIATE": round((100.0 * p_malicious) - (fp_cost * p_benign), 2),
        }

        best_action = max(utilities.items(), key=lambda x: x[1])[0]

        return {
            "confidence_score": score,
            "recommended_action": best_action,
            "expected_utilities": utilities,
            "is_blocking": best_action in ("QUARANTINE", "BLOCK_IMMEDIATE"),
        }
