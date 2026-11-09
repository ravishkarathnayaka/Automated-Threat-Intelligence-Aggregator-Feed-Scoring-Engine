"""Unit tests for Fox-IT JA4H HTTP client fingerprint analyzer."""

from cti_core.processors.ja4h_http_processor import JA4HFingerprintProcessor


def test_ja4h_validation_and_classification():
    # Known Cobalt Strike HTTP beacon
    cs_fp = "ge11nn040000_8daaf6152771_000000000000_000000000000"
    assert JA4HFingerprintProcessor.is_valid_ja4h(cs_fp) is True
    penalty, desc = JA4HFingerprintProcessor.evaluate(cs_fp)
    assert penalty == 35.0
    assert "Cobalt Strike" in desc

    # Suspicious minimal header count
    min_fp = "ge11nn020000_111111111111_000000000000_000000000000"
    penalty2, desc2 = JA4HFingerprintProcessor.evaluate(min_fp)
    assert penalty2 == 15.0
    assert "suspicious_minimal" in desc2

    # Normal browser fingerprint
    norm_fp = "ge20cr12enus_111111111111_222222222222_333333333333"
    penalty3, desc3 = JA4HFingerprintProcessor.evaluate(norm_fp)
    assert penalty3 == 0.0
    assert desc3 == "unclassified_ja4h"

    # Invalid / Missing
    assert JA4HFingerprintProcessor.evaluate(None)[1] == "missing_ja4h"
    assert JA4HFingerprintProcessor.evaluate("bad_ja4h")[1] == "invalid_ja4h_format"
