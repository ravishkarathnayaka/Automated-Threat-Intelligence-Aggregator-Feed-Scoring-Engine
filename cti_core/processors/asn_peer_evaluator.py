"""BGP upstream transit provider and ASN peer relationship risk evaluator."""

from typing import Dict, List, Optional, Tuple


class ASNPeerEvaluator:
    """Evaluates threat risk based on BGP upstream transit provider reputation."""

    # Upstream transits frequently observed carrying unpoliced rogue prefixes
    RISKY_TRANSIT_PROVIDERS: Dict[str, Tuple[float, str]] = {
        "AS49870": (20.0, "Alsycon B.V. bulletproof transit"),
        "AS204957": (20.0, "Green Floid offshore transit"),
        "AS62005": (15.0, "BlueVPS transit node"),
        "AS200019": (25.0, "Alexhost upstream transit"),
    }

    # Highly regulated Tier-1 backbones with strict RPKI ROA enforcement
    TIER1_BACKBONES: Dict[str, str] = {
        "AS174": "Cogent Communications",
        "AS3356": "Lumen (CenturyLink)",
        "AS2914": "NTT America",
        "AS1299": "Arelion (Telia)",
        "AS6939": "Hurricane Electric",
    }

    @classmethod
    def evaluate_peers(cls, upstream_asns: Optional[List[str]]) -> Tuple[float, List[str]]:
        """Evaluates upstream transit risk.

        Returns:
            Tuple[float, List[str]]: (cumulative_penalty, list_of_diagnostics)
        """
        if not upstream_asns:
            return 0.0, ["no_upstream_peers"]

        total_penalty = 0.0
        diagnostics = []

        for asn in upstream_asns:
            clean = asn.strip().upper()
            if not clean.startswith("AS"):
                clean = f"AS{clean}"

            if clean in cls.RISKY_TRANSIT_PROVIDERS:
                penalty, desc = cls.RISKY_TRANSIT_PROVIDERS[clean]
                total_penalty += penalty
                diagnostics.append(f"risky_upstream: {clean} ({desc})")

            elif clean in cls.TIER1_BACKBONES:
                diagnostics.append(f"tier1_transit: {clean} ({cls.TIER1_BACKBONES[clean]})")

        return round(min(40.0, total_penalty), 2), diagnostics
