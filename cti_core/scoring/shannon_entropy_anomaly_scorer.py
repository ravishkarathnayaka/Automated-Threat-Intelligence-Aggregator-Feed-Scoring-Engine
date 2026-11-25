"""Sliding-window symbol entropy and zlib compression ratio anomaly scoring model."""

import math
import zlib
from collections import Counter
from typing import Dict, Optional


class EntropyCompressionScorer:
    """Combines Shannon character entropy with Lempel-Ziv compression ratio to detect obfuscated payload strings."""

    @classmethod
    def analyze(cls, text: Optional[str]) -> Dict[str, float]:
        """Calculates Shannon entropy and Deflate compression ratio.

        Returns:
            Dict containing shannon_entropy, compression_ratio, combined_anomaly_score.
        """
        if not text:
            return {
                "shannon_entropy": 0.0,
                "compression_ratio": 1.0,
                "anomaly_score": 0.0,
            }

        length = len(text)
        counts = Counter(text)
        entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())

        raw_bytes = text.encode("utf-8")
        compressed_len = len(zlib.compress(raw_bytes, level=6))
        ratio = round(compressed_len / max(1, len(raw_bytes)), 4)

        # High entropy (> 4.2) and low compressibility (ratio > 0.85) indicates high-entropy encrypted/packed payloads
        norm_entropy = min(1.0, entropy / 6.0)
        norm_ratio = min(1.0, ratio)
        combined = round((0.6 * norm_entropy + 0.4 * norm_ratio) * 100.0, 2)

        return {
            "shannon_entropy": round(entropy, 4),
            "compression_ratio": ratio,
            "anomaly_score": combined,
        }
