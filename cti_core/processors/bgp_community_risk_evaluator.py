"""BGP route community tag and blackhole signaling risk evaluator."""

from typing import Dict, List, Optional, Tuple


class BGPCommunityRiskEvaluator:
    """Evaluates standard and extended BGP community attributes attached to Autonomous System routes."""

    # Well-known and threat-relevant BGP community attributes
    RISK_COMMUNITIES: Dict[str, Tuple[float, str]] = {
        "65535:666": (35.0, "RFC 7999 Well-known Blackhole community (Active DDoS mitigation / null-route)"),
        "65535:65281": (20.0, "RFC 1997 NO_EXPORT community in public routing table"),
        "65535:65282": (20.0, "RFC 1997 NO_ADVERTISE community in public routing table"),
        "200019:666": (30.0, "Bulletproof host internal blackhole route"),
        "13335:10001": (15.0, "DDoS scrubbing tunnel transit redirect"),
    }

    @classmethod
    def evaluate(cls, communities: List[str]) -> Tuple[float, List[str]]:
        """Evaluates a list of BGP community strings (e.g. ['65535:666', '1239:100']).

        Returns:
            Tuple[float, List[str]]: (risk_penalty, detected_flags)
        """
        if not communities:
            return 0.0, []

        penalty = 0.0
        flags: List[str] = []

        for comm in communities:
            clean = comm.strip()
            if clean in cls.RISK_COMMUNITIES:
                pts, desc = cls.RISK_COMMUNITIES[clean]
                penalty += pts
                flags.append(desc)

        return round(min(50.0, penalty), 2), flags
