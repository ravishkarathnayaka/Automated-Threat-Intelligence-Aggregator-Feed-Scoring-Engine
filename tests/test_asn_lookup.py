"""Unit tests for ASN reputation processor."""

from cti_core.processors.asn_lookup import ASNReputationProcessor


def test_bulletproof_asn():
    penalty, desc = ASNReputationProcessor.evaluate("AS200019")
    assert penalty == 35.0
    assert "Alexhost" in desc

    penalty_num, desc_num = ASNReputationProcessor.evaluate("44477")
    assert penalty_num == 30.0
    assert "Stark Industries" in desc_num


def test_hyperscaler_asn():
    penalty, desc = ASNReputationProcessor.evaluate("AS16509")
    assert penalty == 0.0
    assert "Amazon" in desc


def test_unknown_asn():
    penalty, desc = ASNReputationProcessor.evaluate(None)
    assert penalty == 0.0
    assert desc == "unknown_asn"
