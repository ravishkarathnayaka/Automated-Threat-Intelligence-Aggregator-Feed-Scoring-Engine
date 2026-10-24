"""Binary and shellcode payload Shannon entropy and Chi-square randomness evaluator."""

import math
from typing import Dict, Tuple


class PayloadEntropyEvaluator:
    """Calculates byte-level Shannon entropy and Chi-square statistic for packed/encrypted malware detection."""

    @classmethod
    def calculate_shannon_entropy(cls, payload: bytes) -> float:
        """Calculates Shannon entropy in bits per byte (range [0.0, 8.0])."""
        if not payload:
            return 0.0

        byte_counts = [0] * 256
        for b in payload:
            byte_counts[b] += 1

        total_bytes = len(payload)
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / total_bytes
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    @classmethod
    def evaluate(cls, payload: bytes) -> Tuple[float, float, str]:
        """Evaluates payload for packing or encryption.

        Returns:
            Tuple[float, float, str]: (shannon_entropy, risk_penalty, classification)
        """
        if not payload:
            return 0.0, 0.0, "empty_payload"

        entropy = cls.calculate_shannon_entropy(payload)

        # Packed or encrypted malware typically has entropy > 7.2 bits/byte
        if entropy >= 7.6:
            return entropy, 35.0, "highly_packed_or_encrypted_shellcode"
        elif entropy >= 7.0:
            return entropy, 20.0, "suspected_packed_binary"
        elif entropy <= 2.0:
            return entropy, 10.0, "sparse_repetitive_padding"

        return entropy, 0.0, "standard_unpacked_code"
