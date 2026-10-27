"""Unit tests for TLS ALPN classifier."""

from cti_core.processors.tls_alpn_classifier import TLSALPNClassifier


def test_tls_alpn_evaluation():
    # Standard browser ALPN
    is_susp, penalty, desc = TLSALPNClassifier.evaluate(["h2", "http/1.1"])
    assert is_susp is False
    assert penalty == 0.0
    assert desc == "standard_web_alpn"

    # Covert C2 ALPN
    is_susp, penalty, desc = TLSALPNClassifier.evaluate(["c2", "http/1.1"])
    assert is_susp is True
    assert penalty == 35.0
    assert "custom C2" in desc

    # Non-standard proprietary ALPN
    is_susp, penalty, desc = TLSALPNClassifier.evaluate(["custom_proto_v1"])
    assert is_susp is True
    assert penalty == 20.0
    assert "non_standard" in desc

    # Missing ALPN
    is_susp, penalty, desc = TLSALPNClassifier.evaluate([])
    assert is_susp is True
    assert penalty == 10.0
    assert "missing" in desc
