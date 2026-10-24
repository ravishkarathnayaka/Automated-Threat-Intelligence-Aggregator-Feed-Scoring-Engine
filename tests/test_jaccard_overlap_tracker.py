"""Unit tests for pairwise Jaccard overlap tracker."""

from cti_core.scoring.jaccard_overlap_tracker import JaccardOverlapTracker


def test_jaccard_index_computation():
    set_a = {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
    set_b = {"2.2.2.2", "3.3.3.3", "4.4.4.4"}
    # intersection: 2 ('2.2.2.2', '3.3.3.3'), union: 4
    assert JaccardOverlapTracker.jaccard_index(set_a, set_b) == 0.5


def test_evaluate_feed_overlap():
    feeds = {
        "vendor_alpha": ["198.51.100.1", "198.51.100.2", "198.51.100.3"],
        "vendor_beta": ["198.51.100.1", "198.51.100.2", "198.51.100.3"],  # 100% duplicate
        "vendor_gamma": ["203.0.113.1", "203.0.113.2"],  # disjoint
    }

    results = JaccardOverlapTracker.evaluate_feed_overlap(feeds, redundancy_threshold=0.8)
    assert len(results) == 3
    # Top pair is alpha and beta
    assert results[0][0] == "vendor_alpha"
    assert results[0][1] == "vendor_beta"
    assert results[0][2] == 1.0
    assert results[0][3] is True  # marked redundant
