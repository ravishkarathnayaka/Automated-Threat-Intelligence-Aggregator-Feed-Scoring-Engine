"""Unit tests for BGP ASN peer evaluator."""

from cti_core.processors.asn_peer_evaluator import ASNPeerEvaluator


def test_risky_upstream_peer():
    penalty, diags = ASNPeerEvaluator.evaluate_peers(["AS49870", "AS174"])
    assert penalty == 20.0
    assert any("Alsycon" in d for d in diags)
    assert any("Cogent" in d for d in diags)


def test_clean_tier1_peers():
    penalty, diags = ASNPeerEvaluator.evaluate_peers(["AS3356", "AS1299"])
    assert penalty == 0.0
    assert len(diags) == 2


def test_empty_peers():
    penalty, diags = ASNPeerEvaluator.evaluate_peers([])
    assert penalty == 0.0
    assert "no_upstream_peers" in diags
