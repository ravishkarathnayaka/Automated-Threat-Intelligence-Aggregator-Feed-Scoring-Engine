"""User-Agent string structural anomaly and randomness evaluator."""

import math
from typing import Optional, Tuple


class UserAgentAnomalyDetector:
    """Evaluates User-Agent strings for randomness, missing standard browser tokens, and structural anomalies."""

    @classmethod
    def calculate_entropy(cls, text: str) -> float:
        """Shannon entropy of character distribution."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return round(-sum(p * math.log2(p) for p in prob), 3)

    @classmethod
    def evaluate(cls, user_agent: Optional[str]) -> Tuple[float, str]:
        """Evaluates whether User-Agent exhibits scanner or DGA-like random behavior.

        Returns:
            Tuple[float, str]: (penalty_score, verdict)
        """
        if not user_agent or not user_agent.strip():
            return 25.0, "empty_user_agent"

        ua = user_agent.strip()

        # Dangerously short or single-word strings (e.g. 'curl', 'Python', 'Go-http-client', 'test')
        if len(ua) < 10 and not any(k in ua.lower() for k in ["opera", "lynx"]):
            return 20.0, "atypically_short_user_agent"

        entropy = cls.calculate_entropy(ua)

        # High entropy without standard platform syntax
        has_mozilla = "mozilla" in ua.lower()
        has_platform = any(k in ua.lower() for k in ["windows", "macintosh", "linux", "android", "iphone"])

        if entropy > 4.6 and not (has_mozilla and has_platform):
            return 30.0, f"high_entropy_random_agent (entropy: {entropy})"

        if not has_mozilla and not has_platform:
            return 15.0, "non_standard_http_client"

        return 0.0, "standard_browser_signature"
