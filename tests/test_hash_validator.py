"""Unit tests verifying cryptographic hash validation and format identification."""

from cti_core.processors.hash_validator import HashValidator


def test_hash_type_identification():
    """Verify MD5, SHA1, SHA256, SHA512, and SSDEEP detection."""
    md5_sample = "c4ca4238a0b923820dcc509a6f75849b"
    sha1_sample = "356a192b7913b04c54574d18c28d46e6395428ab"
    sha256_sample = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
    ssdeep_sample = "384:p0y4bH3XvG:p0y4bH3XvG"

    assert HashValidator.identify_hash_type(md5_sample) == "md5"
    assert HashValidator.identify_hash_type(sha1_sample) == "sha1"
    assert HashValidator.identify_hash_type(sha256_sample) == "sha256"
    assert HashValidator.identify_hash_type(ssdeep_sample) == "ssdeep"
    assert HashValidator.identify_hash_type("not-a-hash") is None


def test_validate_hash():
    """Verify hash validation and normalization."""
    valid, htype, norm = HashValidator.validate_hash("  6B86B273FF34FCE19D6B804EFF5A3F5747ADA4EAA22F1D49C01E52DDB7875B4B  ")
    assert valid is True
    assert htype == "sha256"
    assert norm == "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"


def test_known_empty_hashes():
    """Verify zero and empty string hashes are flagged."""
    assert HashValidator.is_known_null_or_zero_hash("d41d8cd98f00b204e9800998ecf8427e") is True
    assert HashValidator.is_known_null_or_zero_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True
    assert HashValidator.is_known_null_or_zero_hash("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b") is False
