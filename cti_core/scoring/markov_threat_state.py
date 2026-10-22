"""Discrete Markov chain threat infrastructure life cycle transition model."""

from enum import Enum
from typing import Dict, List, Tuple


class ThreatState(str, Enum):
    DORMANT = "dormant"
    ACTIVE = "active"
    MONITORED = "monitored"
    REMEDIATED = "remediated"


class MarkovThreatStateModel:
    """Simulates threat infrastructure state transitions using stochastic Markov transition matrices."""

    # Default transition probabilities P(next_state | current_state)
    TRANSITION_MATRIX: Dict[ThreatState, Dict[ThreatState, float]] = {
        ThreatState.DORMANT: {
            ThreatState.DORMANT: 0.85,
            ThreatState.ACTIVE: 0.12,
            ThreatState.MONITORED: 0.02,
            ThreatState.REMEDIATED: 0.01,
        },
        ThreatState.ACTIVE: {
            ThreatState.DORMANT: 0.05,
            ThreatState.ACTIVE: 0.70,
            ThreatState.MONITORED: 0.15,
            ThreatState.REMEDIATED: 0.10,
        },
        ThreatState.MONITORED: {
            ThreatState.DORMANT: 0.20,
            ThreatState.ACTIVE: 0.15,
            ThreatState.MONITORED: 0.50,
            ThreatState.REMEDIATED: 0.15,
        },
        ThreatState.REMEDIATED: {
            ThreatState.DORMANT: 0.05,
            ThreatState.ACTIVE: 0.02,
            ThreatState.MONITORED: 0.03,
            ThreatState.REMEDIATED: 0.90,
        },
    }

    @classmethod
    def step_probability(cls, current_state: ThreatState) -> Dict[ThreatState, float]:
        """Returns the probability distribution for the next state step."""
        return cls.TRANSITION_MATRIX.get(current_state, cls.TRANSITION_MATRIX[ThreatState.DORMANT])

    @classmethod
    def simulate_trajectory(
        cls,
        initial_state: ThreatState = ThreatState.ACTIVE,
        steps: int = 5,
    ) -> List[Dict[str, float]]:
        """Computes marginal state probabilities across n discrete time steps."""
        state_probs: Dict[ThreatState, float] = {s: (1.0 if s == initial_state else 0.0) for s in ThreatState}
        trajectory: List[Dict[str, float]] = [{s.value: round(v, 4) for s, v in state_probs.items()}]

        for _ in range(steps):
            next_probs: Dict[ThreatState, float] = {s: 0.0 for s in ThreatState}
            for curr_s, prob in state_probs.items():
                transitions = cls.TRANSITION_MATRIX[curr_s]
                for target_s, p_trans in transitions.items():
                    next_probs[target_s] += prob * p_trans
            state_probs = next_probs
            trajectory.append({s.value: round(v, 4) for s, v in state_probs.items()})

        return trajectory
