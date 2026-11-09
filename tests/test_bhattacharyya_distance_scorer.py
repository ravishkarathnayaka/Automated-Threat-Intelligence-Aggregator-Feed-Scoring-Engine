"""Unit tests for Bhattacharyya Distance threat actor attribution scorer."""

from cti_core.scoring.bhattacharyya_distance_scorer import BhattacharyyaDistanceScorer


def test_bhattacharyya_distance():
    apt_a = {"T1059": 10.0, "T1071": 8.0, "cobalt-strike": 12.0}
    apt_b = {"T1059": 9.0, "T1071": 8.5, "cobalt-strike": 11.0}
    bc, dist, match = BhattacharyyaDistanceScorer.compute_distance(apt_a, apt_b)
    assert bc > 0.99
    assert dist < 0.02
    assert "high_confidence" in match

    # Disjoint profiles
    apt_c = {"T1486": 15.0, "lockbit": 20.0}
    bc2, dist2, match2 = BhattacharyyaDistanceScorer.compute_distance(apt_a, apt_c)
    assert bc2 == 0.0
    assert "distinct" in match2
