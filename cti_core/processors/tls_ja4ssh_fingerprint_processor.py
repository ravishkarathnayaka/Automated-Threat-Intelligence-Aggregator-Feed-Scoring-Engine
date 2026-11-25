"""Fox-IT JA4SSH SSH client and server interactive tunnel fingerprint analyzer."""

import re
from typing import Dict, Optional, Tuple


class JA4SSHFingerprintProcessor:
    """Evaluates Fox-IT JA4SSH fingerprints to distinguish automated brute-force tools from interactive shells."""

    # Format: [c|s]_[0-9]+_[0-9]+_[0-9]+_[0-9]+ e.g. c_10_20_15_5
    JA4SSH_PATTERN = re.compile(r"^[cs]_\d+_\d+_\d+_\d+$", re.IGNORECASE)

    KNOWN_MALICIOUS_JA4SSH: Dict[str, Tuple[float, str]] = {
        "c_1_0_0_0": (35.0, "Hydra / Medusa automated SSH password brute-force tool"),
        "c_2_1_0_0": (30.0, "Patator multi-threaded SSH credential dictionary sprayer"),
        "s_5_2_1_0": (30.0, "Kippo / Cowrie SSH honeypot detection evasive daemon"),
        "c_20_15_12_8": (10.0, "Automated Ansible / Paramiko scripted management runner"),
    }

    @classmethod
    def is_valid_ja4ssh(cls, fingerprint: str) -> bool:
        """Validates string against Fox-IT JA4SSH specification."""
        if not fingerprint:
            return False
        return bool(cls.JA4SSH_PATTERN.match(fingerprint.strip()))

    @classmethod
    def evaluate(cls, fingerprint: Optional[str]) -> Tuple[float, str]:
        """Classifies threat risk for a JA4SSH fingerprint.

        Returns:
            Tuple[float, str]: (penalty_score, classification)
        """
        if not fingerprint:
            return 0.0, "missing_ja4ssh"

        clean = fingerprint.strip().lower()
        if not cls.is_valid_ja4ssh(clean):
            return 0.0, "invalid_ja4ssh_format"

        if clean in cls.KNOWN_MALICIOUS_JA4SSH:
            penalty, desc = cls.KNOWN_MALICIOUS_JA4SSH[clean]
            return penalty, f"malicious_ja4ssh: {desc}"

        parts = clean.split("_")
        packets_sent = int(parts[1])
        packets_recv = int(parts[2])

        # Immediate disconnect after auth attempt without interactive keystrokes
        if packets_sent <= 2 and packets_recv <= 1:
            return 25.0, "automated_single_attempt_ssh_probe"

        return 0.0, "standard_interactive_ssh_session"
