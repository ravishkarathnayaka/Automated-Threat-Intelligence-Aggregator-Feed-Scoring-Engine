"""Unit tests for Dempster-Shafer Evidence Theory multi-feed fusion scorer."""

from cti_core.scoring.dempster_shafer_scorer import DempsterShaferScorer


def test_dempster_shafer_corroboration():
    # Two corroborating feeds with moderate belief in maliciousness
    m1 = {"malicious": 0.70, "benign": 0.05, "uncertain": 0.25}
    m2 = {"malicious": 0.80, "benign": 0.05, "uncertain": 0.15}

    res = DempsterShaferScorer.fuse_evidence([m1, m2])
    assert res["belief_malicious"] > 0.85
    assert res["plausibility_malicious"] >= res["belief_malicious"]
    assert res["composite_score"] > 85.0
    assert res["conflict_k"] < 0.15


def test_dempster_shafer_high_conflict():
    m1 = {"malicious": 0.90, "benign": 0.0, "uncertain": 0.10}
    m2 = {"malicious": 0.0, "benign": 0.85, "uncertain": 0.15}

    res = DempsterShaferScorer.fuse_evidence([m1, m2])
    assert res["conflict_k"] > 0.70
