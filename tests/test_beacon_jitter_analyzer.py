"""Unit tests for C2 beacon jitter analyzer."""

from cti_core.processors.beacon_jitter_analyzer import BeaconJitterAnalyzer


def test_strict_beaconing():
    # Exactly 60 seconds interval with tiny drift
    timestamps = [100.0, 160.0, 220.1, 280.0, 340.2, 400.0]
    is_beacon, cv, penalty, desc = BeaconJitterAnalyzer.analyze_intervals(timestamps)
    assert is_beacon is True
    assert cv < 0.05
    assert penalty == 35.0
    assert "strict_periodic" in desc


def test_jittered_beaconing():
    # Mean interval ~60s with ~25% randomized jitter
    timestamps = [100.0, 145.0, 220.0, 268.0, 340.0, 390.0]
    is_beacon, cv, penalty, desc = BeaconJitterAnalyzer.analyze_intervals(timestamps)
    assert is_beacon is True
    assert 0.15 <= cv < 0.35
    assert penalty >= 25.0
    assert "jittered_c2" in desc


def test_sporadic_traffic():
    # Highly variable human intervals (1s, 120s, 3s, 500s)
    timestamps = [10.0, 11.0, 131.0, 134.0, 634.0]
    is_beacon, cv, penalty, desc = BeaconJitterAnalyzer.analyze_intervals(timestamps)
    assert is_beacon is False
    assert cv > 0.50
    assert penalty == 0.0
