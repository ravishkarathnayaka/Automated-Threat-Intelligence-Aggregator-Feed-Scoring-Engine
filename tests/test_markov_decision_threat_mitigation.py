"""Unit tests for Markov Decision Process threat mitigation engine."""

from cti_core.scoring.markov_decision_threat_mitigation import ThreatMitigationMDP


def test_mdp_mitigation_actions():
    # Low confidence -> Alert or Allow
    low = ThreatMitigationMDP.evaluate_optimal_action(confidence_score=20.0)
    assert low["recommended_action"] in ("ALLOW", "ALERT")
    assert low["is_blocking"] is False

    # Very high confidence (95%) -> BLOCK_IMMEDIATE
    high = ThreatMitigationMDP.evaluate_optimal_action(confidence_score=95.0)
    assert high["recommended_action"] == "BLOCK_IMMEDIATE"
    assert high["is_blocking"] is True

    # High business sensitivity on moderate confidence -> TARPIT / QUARANTINE
    med = ThreatMitigationMDP.evaluate_optimal_action(confidence_score=75.0, business_impact_weight=1.5)
    assert med["recommended_action"] in ("QUARANTINE", "BLOCK_IMMEDIATE", "TARPIT")
