"""Unit tests for X.509 certificate serial number normalizer."""

from cti_core.processors.certificate_serial_normalizer import CertificateSerialNormalizer


def test_normalize_colon_hex_serial():
    raw = "04:A1:B2:C3:D4:E5"
    norm = CertificateSerialNormalizer.normalize_serial(raw)
    assert norm == "04a1b2c3d4e5"
    presentation = CertificateSerialNormalizer.format_colon_hex(norm)
    assert presentation == "04:a1:b2:c3:d4:e5"


def test_normalize_space_hex_serial():
    raw = "04 A1 B2 C3"
    norm = CertificateSerialNormalizer.normalize_serial(raw)
    assert norm == "04a1b2c3"


def test_normalize_invalid_serial():
    assert CertificateSerialNormalizer.normalize_serial("") is None
    assert CertificateSerialNormalizer.normalize_serial("invalid_serial!@#") is None
