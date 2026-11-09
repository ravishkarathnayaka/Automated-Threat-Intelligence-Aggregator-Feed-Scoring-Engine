"""Unit tests for Thompson Sampling Multi-Armed Bandit feed scheduler."""

from cti_core.scoring.thompson_sampling_bandit import ThompsonSamplingBandit


def test_thompson_sampling_bandit_ranking():
    bandit = ThompsonSamplingBandit()
    bandit.register_feed("high_yield_c2_feed")
    bandit.register_feed("noisy_osint_feed")

    bandit.record_outcome("high_yield_c2_feed", actionable_hits=45, false_positives=2)
    bandit.record_outcome("noisy_osint_feed", actionable_hits=5, false_positives=40)

    ranked = bandit.rank_feeds_deterministic()
    assert len(ranked) == 2
    assert ranked[0]["feed_name"] == "high_yield_c2_feed"
    assert ranked[0]["priority_index"] > ranked[1]["priority_index"]
