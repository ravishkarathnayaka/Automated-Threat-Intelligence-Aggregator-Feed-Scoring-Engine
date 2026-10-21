"""Malicious HTTP User-Agent fingerprint validator and automated scanner classifier."""

from typing import Dict, Optional, Tuple


class UserAgentValidator:
    """Classifies suspicious HTTP User-Agent strings used by offensive scanners and malware beacons."""

    # Known offensive scanning tools and malware beacon headers
    KNOWN_ATTACK_AGENTS: Dict[str, Tuple[str, float]] = {
        "sqlmap": ("SQL Injection automation tool", 95.0),
        "nikto": ("Web vulnerability scanner", 90.0),
        "masscan": ("Mass port scanner", 85.0),
        "zgrab": ("L7 network banner grabber", 80.0),
        "nmap": ("Network mapper scanner", 85.0),
        "havoc": ("Havoc C2 framework client", 98.0),
        "sliver": ("Sliver adversary emulation C2", 98.0),
        "gobuster": ("Directory brute-force scanner", 85.0),
        "dirbuster": ("Web path brute-forcer", 85.0),
    }

    @classmethod
    def evaluate(cls, user_agent: Optional[str]) -> Tuple[bool, float, str]:
        """Evaluate if User-Agent string is a known attack or scanner signature.

        Returns:
            Tuple[bool, float, str]: (is_malicious, confidence_score, classification)
        """
        if not user_agent:
            return False, 0.0, "missing_user_agent"

        ua_lower = user_agent.strip().lower()
        for pattern, (desc, score) in cls.KNOWN_ATTACK_AGENTS.items():
            if pattern in ua_lower:
                return True, score, f"scanner_tool: {desc}"

        # Anonymized / spoofed empty or default Python/Go clients
        if ua_lower in ("python-requests/2.28.1", "go-http-client/1.1", "mozilla/5.0"):
            return False, 50.0, "generic_script_client"

        return False, 0.0, "benign_browser_agent"
