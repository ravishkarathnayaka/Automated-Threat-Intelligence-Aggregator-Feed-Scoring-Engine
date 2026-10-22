"""Unit tests for Markov threat state transition model."""

from cti_core.scoring.markov_threat_state import MarkovThreatStateModel, ThreatState


def test_markov_step_probability_sum():
    probs = MarkovThreatStateModel.step_probability(ThreatState.ACTIVE)
    assert abs(sum(probs.values()) - 1.0) < 1e-4
    assert probs[ThreatState.ACTIVE] == 0.70


def test_markov_trajectory_simulation():
    trajectory = MarkovThreatStateModel.simulate_trajectory(initial_state=ThreatState.ACTIVE, steps=3)
    assert len(trajectory) == 4
    # Step 0: active is 1.0
    assert trajectory[0]["active"] == 1.0
    # Steps 1..3: active probability slowly diffuses into monitored and remediated
    assert trajectory[3]["active"] < 1.0
    assert trajectory[3]["remediated"] > 0.0
