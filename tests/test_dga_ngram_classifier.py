"""Unit tests for DGA N-gram classifier."""

from cti_core.processors.dga_ngram_classifier import DGANgramClassifier


def test_dga_unnatural_bigrams():
    score, reason = DGANgramClassifier.evaluate("qxzxvkqj.com")
    assert score >= 70.0
    assert "rare_bigrams" in reason or "low_natural" in reason


def test_natural_english_domain():
    score, reason = DGANgramClassifier.evaluate("authenticationserver.com")
    assert score <= 10.0
    assert reason == "natural_bigram_transitions"


def test_short_domain():
    score, reason = DGANgramClassifier.evaluate("abc.com")
    assert score == 0.0
    assert reason == "label_too_short"
