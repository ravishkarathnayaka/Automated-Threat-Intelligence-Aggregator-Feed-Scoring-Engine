"""Unit tests for PageRank threat graph model."""

from cti_core.scoring.pagerank_threat_graph import PageRankThreatGraph


def test_pagerank_threat_centrality():
    # Central C2 IP connected to 3 malicious domains and 2 malware hashes
    edges = [
        ("198.51.100.1", "c2-domain-1.com"),
        ("198.51.100.1", "c2-domain-2.com"),
        ("198.51.100.1", "c2-domain-3.com"),
        ("198.51.100.1", "hash-payload-aaa"),
        ("c2-domain-1.com", "hash-payload-bbb"),
    ]

    ranks = PageRankThreatGraph.compute_pagerank(edges)

    assert len(ranks) == 6
    # The central IP node has highest degree and should hold the maximum PageRank score (1.0 normalized)
    assert ranks["198.51.100.1"] == 1.0
    assert ranks["c2-domain-1.com"] > ranks["c2-domain-2.com"]


def test_pagerank_empty():
    assert PageRankThreatGraph.compute_pagerank([]) == {}
