"""Unit tests for ssdeep fuzzy hash comparator."""

from cti_core.processors.ssdeep_comparator import SSDeepComparator


def test_ssdeep_validity():
    valid = "384:6Y4b7P9a8bC/dEf:6YbC/dE"
    assert SSDeepComparator.is_valid(valid) is True
    assert SSDeepComparator.is_valid("not_a_hash") is False


def test_ssdeep_identical_match():
    h = "192:6Y4b7P9a8bC/dEfGH:6YbC/dEGH"
    sim = SSDeepComparator.calculate_similarity(h, h)
    assert sim == 100


def test_ssdeep_different_block_size():
    h1 = "96:abcde:fghij"
    h2 = "768:abcde:fghij"  # 8x difference -> incompatible
    sim = SSDeepComparator.calculate_similarity(h1, h2)
    assert sim == 0
