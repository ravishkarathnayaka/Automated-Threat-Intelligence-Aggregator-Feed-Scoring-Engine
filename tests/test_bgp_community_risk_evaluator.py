"""Unit tests for BGP community risk evaluator."""

from cti_core.processors.bgp_community_risk_evaluator import BGPCommunityRiskEvaluator


def test_bgp_community_evaluation():
    # RFC 7999 Blackhole community
    penalty, flags = BGPCommunityRiskEvaluator.evaluate(["65535:666", "174:21000"])
    assert penalty == 35.0
    assert any("RFC 7999" in f for f in flags)

    # Clean benign ISP community tags
    penalty_clean, flags_clean = BGPCommunityRiskEvaluator.evaluate(["1299:1000", "3356:100"])
    assert penalty_clean == 0.0
    assert len(flags_clean) == 0

    # Empty list
    penalty_empty, flags_empty = BGPCommunityRiskEvaluator.evaluate([])
    assert penalty_empty == 0.0
    assert len(flags_empty) == 0
