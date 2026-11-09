"""Unit tests for Hawkes Self-Exciting Point Process campaign burst model."""

from cti_core.scoring.hawkes_process_intensity import HawkesProcessIntensityModel


def test_hawkes_process_clustered_swarm():
    # Rapidly clustered sightings near t=10.0
    events = [9.1, 9.4, 9.6, 9.8, 9.9, 10.0]
    lam, br, boost, regime = HawkesProcessIntensityModel.compute_intensity(
        events,
        evaluation_time=10.0,
        baseline_mu=0.10,
        excitation_alpha=0.85,
        decay_beta=1.20,
    )
    assert lam > 3.0
    assert br == 0.7083
    assert boost > 20.0
    assert "supercritical" in regime


def test_hawkes_process_decayed():
    # Old sighting far in the past
    events = [1.0]
    lam, _, boost, regime = HawkesProcessIntensityModel.compute_intensity(
        events,
        evaluation_time=50.0,
    )
    assert abs(lam - 0.10) < 0.01
    assert boost == 0.0
    assert regime == "subcritical_background_noise"
