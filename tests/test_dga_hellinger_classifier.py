"""Unit tests for DGA Hellinger distance classifier."""

from cti_core.processors.dga_hellinger_classifier import DGAHellingerClassifier


def test_dga_hellinger_evaluation():
    # Natural language domain
    is_dga, dist, penalty, desc = DGAHellingerClassifier.evaluate("informationsecuritynews.com")
    assert is_dga is False
    assert dist < 0.45
    assert penalty == 0.0

    # High-entropy random DGA (e.g. Conficker / Gameover Zeus style)
    is_dga, dist, penalty, desc = DGAHellingerClassifier.evaluate("xqzkjqwxxzzkkq.biz")
    assert is_dga is True
    assert dist > 0.65
    assert penalty == 35.0
    assert "high_hellinger" in desc
