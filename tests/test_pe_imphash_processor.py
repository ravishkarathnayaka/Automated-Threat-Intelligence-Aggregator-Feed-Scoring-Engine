"""Unit tests for PE ImpHash and Authenticode signature analyzer."""

from cti_core.processors.pe_imphash_processor import PEImphashProcessor


def test_pe_imphash_evaluation():
    # Known Mimikatz imphash
    mimi_hash = "f34d5f2d4577ed6d9ceec516c1f5a744"
    assert PEImphashProcessor.is_valid_imphash(mimi_hash) is True
    penalty, desc = PEImphashProcessor.evaluate(mimi_hash)
    assert penalty == 35.0
    assert "Mimikatz" in desc

    # Tampered / revoked Authenticode signature on unknown imphash
    unk_hash = "00112233445566778899aabbccddeeff"
    penalty2, desc2 = PEImphashProcessor.evaluate(unk_hash, is_signed=True, signature_valid=False)
    assert penalty2 == 25.0
    assert "authenticode" in desc2

    # Valid signed binary
    penalty3, desc3 = PEImphashProcessor.evaluate(unk_hash, is_signed=True, signature_valid=True)
    assert penalty3 == 0.0
    assert desc3 == "unclassified_pe_imphash"
