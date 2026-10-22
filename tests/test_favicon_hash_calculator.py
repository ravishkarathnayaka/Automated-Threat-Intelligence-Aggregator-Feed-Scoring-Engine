"""Unit tests for favicon MurmurHash3 calculator."""

from cti_core.processors.favicon_hash_calculator import FaviconHashCalculator, murmurhash3_32


def test_murmurhash3_deterministic():
    data = b"Hello Threat Intel World"
    h1 = murmurhash3_32(data)
    h2 = murmurhash3_32(data)
    assert h1 == h2
    assert isinstance(h1, int)


def test_favicon_calculation_and_matching():
    sample_ico = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00"
    h = FaviconHashCalculator.calculate_hash(sample_ico)
    assert isinstance(h, int)

    # Test known threat match
    penalty, verdict = FaviconHashCalculator.evaluate_hash(-123456789)
    assert penalty == 30.0
    assert "Cobalt Strike" in verdict

    # Test clean/unknown icon
    penalty, verdict = FaviconHashCalculator.evaluate_hash(12345)
    assert penalty == 0.0
    assert verdict == "unclassified_favicon"
