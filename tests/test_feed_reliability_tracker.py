"""Unit tests for dynamic feed reliability rating tracker."""

from cti_core.scoring.feed_reliability_tracker import FeedReliabilityTracker


def test_feed_reliability_default_baseline():
    tracker = FeedReliabilityTracker()
    assert tracker.get_dynamic_weight("virustotal") == 0.95
    assert tracker.get_dynamic_weight("alienvault") == 0.70
    assert tracker.get_dynamic_weight("unknown_feed") == 0.70


def test_feed_reliability_verification_update():
    tracker = FeedReliabilityTracker()
    # Record 9 true positives and 1 false positive for alienvault
    for _ in range(9):
        tracker.record_verification("alienvault", is_true_positive=True)
    tracker.record_verification("alienvault", is_true_positive=False)

    precision = tracker.get_precision("alienvault")
    # (9 + 1) / (9 + 1 + 2) = 10 / 12 ~ 0.833
    assert 0.80 <= precision <= 0.85

    weight = tracker.get_dynamic_weight("alienvault")
    # Adjusted weight should increase from baseline 0.70
    assert weight > 0.70


def test_feed_reliability_heavy_false_positives():
    tracker = FeedReliabilityTracker()
    # Record 10 false positives
    for _ in range(10):
        tracker.record_verification("bad_feed", is_true_positive=False)

    precision = tracker.get_precision("bad_feed")
    # (0 + 1) / (10 + 2) = 1 / 12 ~ 0.083
    assert precision < 0.10
    weight = tracker.get_dynamic_weight("bad_feed")
    assert weight == 0.20  # clamped to floor 0.20
