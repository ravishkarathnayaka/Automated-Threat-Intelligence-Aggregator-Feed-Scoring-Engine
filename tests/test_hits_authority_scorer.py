"""Unit tests for Kleinberg HITS threat hub and authority centrality scoring model."""

import pytest
from cti_core.scoring.hits_authority_scorer import HITSAuthorityScorer


def test_empty_graph():
    scorer = HITSAuthorityScorer()
    hubs, auths = scorer.compute_hits({})
    assert hubs == {}
    assert auths == {}


def test_simple_star_topology():
    # Node "pivot_dns" points to malicious c2_1, c2_2, c2_3
    # Node "pivot_proxy" points to c2_1, c2_2
    graph = {
        "pivot_dns": ["c2_1", "c2_2", "c2_3"],
        "pivot_proxy": ["c2_1", "c2_2"],
    }
    scorer = HITSAuthorityScorer()
    hubs, auths = scorer.compute_hits(graph)

    # pivot_dns should have higher hub score than pivot_proxy
    assert hubs["pivot_dns"] > hubs["pivot_proxy"]
    # c2_1 and c2_2 should have higher authority score than c2_3
    assert auths["c2_1"] > auths["c2_3"]
    assert auths["c2_2"] > auths["c2_3"]


def test_evaluate_top_n():
    graph = {
        "asn_bad": ["bot_1", "bot_2", "bot_3"],
        "asn_med": ["bot_1"],
    }
    res = HITSAuthorityScorer.evaluate(graph, top_n=1)
    assert "asn_bad" in res["hubs"]
    assert "bot_1" in res["authorities"]
