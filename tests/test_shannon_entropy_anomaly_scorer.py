"""Unit tests for Shannon Entropy & Compression anomaly model."""

from cti_core.scoring.shannon_entropy_anomaly_scorer import EntropyCompressionScorer


def test_entropy_compression_scorer():
    # Random high-entropy base64 string
    payload = "V2hpbGUgc3VjaCBjb25maWRlbmNlIGlzIHZhbGlkLCB0aGUgcmFuZG9tIGVuY3J5cHRpb24gcGF5bG9hZCBpcyBhIHByb2JsZW0="
    res = EntropyCompressionScorer.analyze(payload)

    assert res["shannon_entropy"] > 4.0
    assert res["anomaly_score"] > 50.0

    # Low entropy repeating string
    low_res = EntropyCompressionScorer.analyze("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert low_res["shannon_entropy"] == 0.0
    assert low_res["compression_ratio"] < 0.5
