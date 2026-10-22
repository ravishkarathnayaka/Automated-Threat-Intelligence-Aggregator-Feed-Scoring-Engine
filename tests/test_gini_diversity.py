"""Unit tests for Gini-Simpson feed diversity index."""

from cti_core.scoring.gini_feed_diversity import GiniFeedDiversity


def test_gini_zero_diversity_homogeneous_feeds():
    # Feeds all in the same category -> diversity = 0
    feeds = ["abuseipdb", "otx", "alienvault_pulse"]
    d = GiniFeedDiversity.calculate_gini_simpson_index(feeds)
    assert d == 0.0

    mult = GiniFeedDiversity.calculate_diversity_multiplier(feeds)
    assert mult == 1.0


def test_gini_high_diversity_heterogeneous_feeds():
    # Diverse independent feeds across government, malware lab, and honeypot
    feeds = ["cisa_kev", "feodo_tracker", "cins_army", "virustotal"]
    d = GiniFeedDiversity.calculate_gini_simpson_index(feeds)
    assert d >= 0.70

    mult = GiniFeedDiversity.calculate_diversity_multiplier(feeds)
    assert mult > 1.30


def test_gini_single_feed():
    assert GiniFeedDiversity.calculate_gini_simpson_index(["cisa_kev"]) == 0.0
    assert GiniFeedDiversity.calculate_diversity_multiplier(["cisa_kev"]) == 1.0
