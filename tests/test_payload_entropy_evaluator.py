"""Unit tests for binary payload Shannon entropy evaluator."""

import os
from cti_core.processors.payload_entropy_evaluator import PayloadEntropyEvaluator


def test_payload_entropy_evaluation():
    # Random bytes (simulating encrypted shellcode/ransomware)
    random_bytes = os.urandom(2048)
    entropy, penalty, cls_name = PayloadEntropyEvaluator.evaluate(random_bytes)
    assert entropy >= 7.5
    assert penalty == 35.0
    assert "encrypted" in cls_name

    # Repetitive NOP sled (0x90 repeated)
    nop_sled = b"\x90" * 1024
    entropy, penalty, cls_name = PayloadEntropyEvaluator.evaluate(nop_sled)
    assert entropy == 0.0
    assert penalty == 10.0
    assert "padding" in cls_name

    # Normal text/code string
    plain_text = b"SELECT * FROM users WHERE active = 1 AND role = 'admin';"
    entropy, penalty, cls_name = PayloadEntropyEvaluator.evaluate(plain_text)
    assert 2.0 < entropy < 6.5
    assert penalty == 0.0
    assert cls_name == "standard_unpacked_code"
