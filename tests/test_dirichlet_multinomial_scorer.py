"""Unit tests for Dirichlet-Multinomial Bayesian multi-category threat classifier."""

import pytest
from cti_core.scoring.dirichlet_multinomial_scorer import DirichletMultinomialScorer


def test_uniform_prior_probabilities():
    scorer = DirichletMultinomialScorer()
    probs = scorer.update({})
    assert len(probs) == 5
    for cat in probs:
        assert pytest.approx(probs[cat], 0.001) == 0.20


def test_update_c2_dominance():
    scorer = DirichletMultinomialScorer()
    probs = scorer.update({"c2": 45, "malware": 5, "benign": 0})
    assert probs["c2"] > probs["malware"]
    assert probs["c2"] > probs["benign"]
    assert sum(probs.values()) == pytest.approx(1.0, 0.01)


def test_variances_decrease_with_observations():
    scorer = DirichletMultinomialScorer()
    init_vars = scorer.compute_category_variances()

    scorer.update({"c2": 100, "phishing": 50})
    post_vars = scorer.compute_category_variances()

    assert post_vars["c2"] < init_vars["c2"]


def test_entropy_and_composite_score():
    res = DirichletMultinomialScorer.classify({"c2": 50, "malware": 20})
    assert res["dominant_category"] == "c2"
    assert res["composite_threat_score"] > 80.0
    assert res["entropy"] >= 0.0
