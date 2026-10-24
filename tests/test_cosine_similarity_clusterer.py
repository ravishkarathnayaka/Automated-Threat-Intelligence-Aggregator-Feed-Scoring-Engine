"""Unit tests for cosine similarity clusterer."""

from cti_core.scoring.cosine_similarity_clusterer import CosineSimilarityClusterer


def test_cosine_similarity_identical_and_orthogonal():
    tags_a = ["apt29", "cobalt-strike", "spearphishing", "c2"]
    tags_b = ["apt29", "cobalt-strike", "spearphishing", "c2"]
    assert CosineSimilarityClusterer.similarity(tags_a, tags_b) == 1.0

    tags_c = ["cryptominer", "xmrig", "stratum"]
    assert CosineSimilarityClusterer.similarity(tags_a, tags_c) == 0.0


def test_find_affiliated_indicators():
    target = ["ransomware", "lockbit", "extortion"]
    pool = [
        {"value": "198.51.100.1", "tags": ["ransomware", "lockbit", "c2"]},
        {"value": "198.51.100.2", "tags": ["cryptominer", "monero"]},
        {"value": "bad-host.com", "tags": ["ransomware", "lockbit", "extortion", "data-leak"]},
    ]

    matches = CosineSimilarityClusterer.find_affiliated_indicators(target, pool, threshold=0.6)
    assert len(matches) == 2
    assert matches[0][0] == "bad-host.com"
    assert matches[0][1] > 0.8
