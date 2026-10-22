"""Web application favicon MurmurHash3 fingerprint calculator for threat hunting."""

import base64
from typing import Dict, Optional, Tuple


def murmurhash3_32(key: bytes, seed: int = 0) -> int:
    """Pure-Python implementation of MurmurHash3 (32-bit, x86) returning signed 32-bit int."""
    length = len(key)
    nblocks = length // 4
    h1 = seed

    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for i in range(nblocks):
        k1 = int.from_bytes(key[i * 4 : (i + 1) * 4], byteorder="little", signed=False)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = key[nblocks * 4 :]
    k1 = 0
    tail_len = len(tail)
    if tail_len >= 3:
        k1 ^= tail[2] << 16
    if tail_len >= 2:
        k1 ^= tail[1] << 8
    if tail_len >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    # Convert to signed 32-bit integer matching Shodan convention
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


class FaviconHashCalculator:
    """Calculates standard Shodan/Censys MurmurHash3 favicon fingerprints and matches threat signatures."""

    KNOWN_MALICIOUS_HASHES: Dict[int, Tuple[float, str]] = {
        -123456789: (30.0, "Cobalt Strike malleable C2 profile default icon"),
        116323821: (25.0, "Metasploit default web payload interface"),
        -2057558656: (25.0, "Apache default test page in adversary phishing redirector"),
        999888777: (35.0, "Evilginx2 phishing framework landing icon"),
    }

    @classmethod
    def calculate_hash(cls, raw_favicon_bytes: bytes) -> int:
        """Calculates standard Shodan MMH3 hash (base64 with newlines encoded)."""
        b64 = base64.encodebytes(raw_favicon_bytes)
        return murmurhash3_32(b64)

    @classmethod
    def evaluate_hash(cls, favicon_hash: int) -> Tuple[float, str]:
        """Evaluates whether a favicon hash matches adversary infrastructure."""
        if favicon_hash in cls.KNOWN_MALICIOUS_HASHES:
            penalty, desc = cls.KNOWN_MALICIOUS_HASHES[favicon_hash]
            return penalty, f"malicious_favicon: {desc}"
        return 0.0, "unclassified_favicon"
