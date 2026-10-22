"""Unit tests for indicator co-occurrence clusterer."""

from cti_core.processors.co_occurrence_clusterer import CoOccurrenceClusterer


def test_co_occurrence_clustering():
    clusterer = CoOccurrenceClusterer()
    # Campaign A: IP1 - Domain1 - Domain2
    clusterer.add_link("198.51.100.22", "c2-beacon.org")
    clusterer.add_link("c2-beacon.org", "payload-drop.biz")

    # Campaign B: IP2 - Domain3
    clusterer.add_link("203.0.113.88", "unrelated-phish.net")

    clusters = clusterer.find_clusters()
    assert len(clusters) == 2

    c1 = next(c for c in clusters if "198.51.100.22" in c)
    assert len(c1) == 3
    assert "c2-beacon.org" in c1
    assert "payload-drop.biz" in c1

    density = CoOccurrenceClusterer.calculate_campaign_density(c1)
    assert density >= 0.7
