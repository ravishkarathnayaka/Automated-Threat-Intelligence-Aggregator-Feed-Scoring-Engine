"""Unit tests for Bayesian probability confidence updater."""

import pytest
from cti_core.scoring.bayesian_scorer import BayesianScorer


def test_bayesian_scorer_single_source():
    # Prior 0.15 -> odds ~0.176
    # VirusTotal LR = 18 -> posterior odds ~3.176 -> posterior prob ~0.76
    prob = BayesianScorer.update_probability(["virustotal"], prior=0.15)
    assert 0.70 < prob < 0.85
    score = BayesianScorer.compute_bayesian_confidence(["virustotal"], prior=0.15)
    assert 70.0 < score < 85.0


def test_bayesian_scorer_multiple_sources():
    # Combining two strong sources should raise probability very close to 1.0
    prob = BayesianScorer.update_probability(["virustotal", "abuse_ch_threatfox"], prior=0.15)
    assert prob > 0.95
    score = BayesianScorer.compute_bayesian_confidence(["virustotal", "abuse_ch_threatfox"], prior=0.15)
    assert score >= 95.0


def test_bayesian_scorer_benign_evidence_decay():
    # Benign confirmation drops posterior significantly
    prob_clean = BayesianScorer.update_probability(["virustotal"], prior=0.15, benign_confirmations=1)
    prob_unclean = BayesianScorer.update_probability(["virustotal"], prior=0.15, benign_confirmations=0)
    assert prob_clean < prob_unclean
    assert prob_clean < 0.30


def test_bayesian_scorer_invalid_prior():
    with pytest.raises(ValueError):
        BayesianScorer.update_probability(["virustotal"], prior=1.5)
