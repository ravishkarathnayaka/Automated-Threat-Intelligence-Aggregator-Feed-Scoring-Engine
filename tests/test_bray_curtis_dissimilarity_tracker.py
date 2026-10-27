"""Unit tests for Bray-Curtis ecological dissimilarity tracker."""

import pytest
from cti_core.scoring.bray_curtis_dissimilarity_tracker import BrayCurtisDissimilarityTracker


def test_identical_feeds_zero_dissimilarity():
    f1 = {"c2": 50, "malware": 25}
    f2 = {"c2": 50, "malware": 25}
    bc = BrayCurtisDissimilarityTracker.calculate_dissimilarity(f1, f2)
    assert bc == 0.0


def test_completely_disjoint_feeds():
    f1 = {"c2": 50}
    f2 = {"phishing": 50}
    bc = BrayCurtisDissimilarityTracker.calculate_dissimilarity(f1, f2)
    assert bc == 1.0


def test_portfolio_evaluation():
    portfolio = {
        "feed_a": {"c2": 100, "phishing": 0},
        "feed_b": {"c2": 0, "phishing": 100},
        "feed_c": {"c2": 50, "phishing": 50},
    }
    res = BrayCurtisDissimilarityTracker.evaluate_portfolio(portfolio)
    assert res["average_portfolio_uniqueness"] > 0.5
    assert len(res["feed_uniqueness_ranking"]) == 3
