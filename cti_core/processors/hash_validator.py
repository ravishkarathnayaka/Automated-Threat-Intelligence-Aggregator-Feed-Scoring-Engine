"""Cryptographic malware hash validator, format detector, and integrity checker."""

import re
from typing import Optional, Tuple

RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_SHA512 = re.compile(r"^[a-fA-F0-9]{128}$")
RE_SSDEEP = re.compile(r"^[0-9]+:[a-zA-Z0-9/+]{3,}:[a-zA-Z0-9/+]{3,}$")


class HashValidator:
    """Validates and identifies cryptographic malware file hashes."""

    @staticmethod
    def identify_hash_type(hash_str: str) -> Optional[str]:
        """Identify whether a hash string is md5, sha1, sha256, sha512, or ssdeep."""
        cleaned = hash_str.strip()
        if RE_MD5.match(cleaned):
            return "md5"
        if RE_SHA1.match(cleaned):
            return "sha1"
        if RE_SHA256.match(cleaned):
            return "sha256"
        if RE_SHA512.match(cleaned):
            return "sha512"
        if RE_SSDEEP.match(cleaned):
            return "ssdeep"
        return None

    @staticmethod
    def validate_hash(hash_str: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validate a hash string.
        Returns (is_valid, hash_type, normalized_lowercase_hash).
        """
        cleaned = hash_str.strip().lower()
        htype = HashValidator.identify_hash_type(cleaned)
        if htype:
            return True, htype, cleaned
        return False, None, None

    @staticmethod
    def is_known_null_or_zero_hash(hash_str: str) -> bool:
        """Check for common placeholder or zero hashes (e.g. empty string hash)."""
        cleaned = hash_str.strip().lower()
        empty_hashes = {
            "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 of empty string
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 of empty string
            "0" * 32,
            "0" * 40,
            "0" * 64,
            "f" * 32,
            "f" * 40,
            "f" * 64,
        }
        return cleaned in empty_hashes
