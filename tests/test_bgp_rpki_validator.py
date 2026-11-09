"""Unit tests for BGP RPKI Route Origin Validation (ROV) analyzer."""

from cti_core.processors.bgp_rpki_validator import BGPRPKIValidator


def test_bgp_rpki_validation():
    # RPKI Invalid hijack
    is_risk, penalty, desc = BGPRPKIValidator.evaluate_roa(
        origin_asn="AS12345",
        rpki_status="invalid",
        prefix_length=24,
    )
    assert is_risk is True
    assert penalty == 35.0
    assert "hijack" in desc

    # Sub-prefix hijack exceeding ROA maxLength
    is_risk2, penalty2, desc2 = BGPRPKIValidator.evaluate_roa(
        origin_asn="AS13335",
        rpki_status="valid",
        prefix_length=26,
        max_roa_length=24,
    )
    assert is_risk2 is True
    assert penalty2 == 30.0
    assert "subprefix" in desc2

    # Private / Bogon ASN leak
    is_risk3, penalty3, desc3 = BGPRPKIValidator.evaluate_roa(
        origin_asn="AS64512",
        rpki_status="not_found",
    )
    assert is_risk3 is True
    assert penalty3 == 35.0

    # Valid ROA
    is_risk4, penalty4, desc4 = BGPRPKIValidator.evaluate_roa(
        origin_asn="AS15169",
        rpki_status="valid",
        prefix_length=24,
        max_roa_length=24,
    )
    assert is_risk4 is False
    assert penalty4 == 0.0
