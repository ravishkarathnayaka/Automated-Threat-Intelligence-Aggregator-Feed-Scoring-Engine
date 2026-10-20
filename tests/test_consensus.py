"""Unit tests for multi-source consensus scorer."""

from cti_core.scoring.consensus import ConsensusScorer


def test_consensus_reached_auto_block():
    res = ConsensusScorer.evaluate(
        sources=["abuseipdb", "threatfox"],
        base_score=75.0,
        min_sources=2,
    )
    assert res["consensus_reached"] is True
    assert res["source_count"] == 2
    assert res["consensus_adjusted_score"] > 75.0
    assert res["enforcement_action"] == "auto_block"
    assert res["actionable_for_blocklist"] is True


def test_consensus_single_source_quarantine():
    res = ConsensusScorer.evaluate(
        sources=["abuseipdb"],
        base_score=85.0,
        min_sources=2,
    )
    assert res["consensus_reached"] is False
    assert res["source_count"] == 1
    # Single source score should be capped to prevent false positives
    assert res["consensus_adjusted_score"] == 65.0
    assert res["enforcement_action"] == "quarantine_review"
    assert res["actionable_for_blocklist"] is False


def test_cross_domain_consensus():
    # Both are 'reputation' domain
    same_domain_res = ConsensusScorer.evaluate(
        sources=["abuseipdb", "blocklist_de"],
        base_score=80.0,
        min_sources=2,
        require_cross_domain=True,
    )
    assert same_domain_res["consensus_reached"] is False

    # One 'reputation', one 'botnet'
    cross_domain_res = ConsensusScorer.evaluate(
        sources=["abuseipdb", "feodo_tracker"],
        base_score=80.0,
        min_sources=2,
        require_cross_domain=True,
    )
    assert cross_domain_res["consensus_reached"] is True
