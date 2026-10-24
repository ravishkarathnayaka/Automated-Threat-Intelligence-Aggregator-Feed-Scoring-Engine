"""Unit tests for Beta-Binomial conjugate Bayesian scorer."""

from cti_core.scoring.beta_distribution_scorer import BetaDistributionScorer


def test_beta_scorer_updates():
    # Initial prior (1, 4) -> 20%
    scorer = BetaDistributionScorer(prior_alpha=1.0, prior_beta=4.0)
    assert scorer.to_confidence_score() == 20.0

    # Strong malicious corroboration (e.g. 9 malicious feeds, 0 benign)
    mean, var = scorer.update(malicious_reports=9, benign_reports=0)
    # alpha=10, beta=4 -> 10/14 = 71.43%
    assert 0.70 < mean < 0.73
    assert var > 0.0
    assert 70.0 < scorer.to_confidence_score() < 73.0

    # Whitelist counter-evidence arrives
    scorer.update(malicious_reports=0, benign_reports=20)
    # alpha=10, beta=24 -> 10/34 = 29.41%
    assert scorer.to_confidence_score() < 35.0


def test_beta_scorer_convenience_method():
    res = BetaDistributionScorer.calculate_score(malicious_count=15, benign_count=1)
    assert res["confidence_score"] > 75.0
    assert res["epistemic_variance"] < 0.05
