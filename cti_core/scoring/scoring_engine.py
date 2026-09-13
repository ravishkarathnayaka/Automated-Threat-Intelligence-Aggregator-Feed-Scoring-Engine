"""Multi-factor confidence scoring engine based on source reliability, cross-source confirmation, and time decay."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cti_core.models.indicator import ConfidenceTier, ScoreBreakdown
from cti_core.processors.whitelist_filter import WhitelistFilter

# Source Reliability Weights (0.0 - 1.0)
SOURCE_RELIABILITY_WEIGHTS: Dict[str, float] = {
    "cisa_kev": 1.00,       # CISA Known Exploited Vulnerabilities (authoritative)
    "urlhaus": 0.85,        # Abuse.ch URLhaus malware link
    "abuseipdb": 0.85,      # AbuseIPDB crowd-reported high confidence
    "virustotal": 0.80,     # VirusTotal multi-engine consensus
    "otx": 0.75,            # AlienVault OTX pulses
    "threatfox": 0.85,      # Abuse.ch ThreatFox
    "manual_entry": 0.90,   # SOC Analyst manually verified
    "default": 0.60,        # Generic / community feed
}

# Cross-Source Confirmation Factors
CROSS_CONFIRMATION_FACTORS = {
    1: 1.00,
    2: 1.25,
    3: 1.45,
    4: 1.60,
}

# Exponential decay base per day
DECAY_LAMBDA = 0.95


class ScoringEngine:
    """Calculates multi-factor confidence scores for threat indicators."""

    def __init__(self, decay_base: float = DECAY_LAMBDA):
        self.decay_base = decay_base

    def calculate_score(
        self,
        ioc_type: str,
        value: str,
        sources: List[Dict[str, Any]],
        last_seen: Optional[datetime] = None,
        enrichment_data: Optional[Dict[str, Any]] = None,
    ) -> ScoreBreakdown:
        """
        Calculate composite confidence score according to the formula:
        Score = (Source Reliability Weight * 100) * (Cross-Source Confirmation Factor) * (Decay Factor ^ Days Old)
        """
        # Step 1: Whitelist check (Hard override to 0)
        is_whitelisted, whitelist_reason = WhitelistFilter.is_whitelisted(ioc_type, value)
        if is_whitelisted:
            return ScoreBreakdown(
                source_weight=0.0,
                cross_source_factor=1.0,
                decay_factor=1.0,
                days_old=0.0,
                enrichment_boost=0.0,
                raw_calculated_score=0.0,
                final_score=0.0,
                tier=ConfidenceTier.LOW,
                is_whitelisted=True,
                whitelist_reason=whitelist_reason,
            )

        # Step 2: Source Reliability Weight
        distinct_sources = set()
        weights = []
        for src in sources:
            src_name = src.get("source_name") or src.get("source") or "default"
            distinct_sources.add(src_name.lower())
            weight = src.get("source_weight") or SOURCE_RELIABILITY_WEIGHTS.get(src_name.lower(), SOURCE_RELIABILITY_WEIGHTS["default"])
            weights.append(weight)

        max_weight = max(weights) if weights else SOURCE_RELIABILITY_WEIGHTS["default"]

        # Step 3: Cross-Source Confirmation Factor
        source_count = max(1, len(distinct_sources))
        if source_count in CROSS_CONFIRMATION_FACTORS:
            cross_factor = CROSS_CONFIRMATION_FACTORS[source_count]
        else:
            cross_factor = CROSS_CONFIRMATION_FACTORS[4]

        # Step 4: Time Decay Factor
        now = datetime.now(timezone.utc)
        if last_seen is None:
            last_seen = now
        elif last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        days_old = max(0.0, (now - last_seen).total_seconds() / 86400.0)
        decay_factor = self.decay_base ** days_old

        # Step 5: Enrichment Boost
        enrichment_boost = 0.0
        if enrichment_data:
            vt = enrichment_data.get("virustotal", {})
            if isinstance(vt, dict):
                malicious = vt.get("malicious_count", 0)
                if malicious >= 10:
                    enrichment_boost += 10.0
                elif malicious >= 3:
                    enrichment_boost += 5.0

            otx = enrichment_data.get("otx", {})
            if isinstance(otx, dict):
                pulses = otx.get("pulse_count", 0)
                if pulses >= 5:
                    enrichment_boost += 8.0
                elif pulses >= 1:
                    enrichment_boost += 4.0

        # Base mathematical calculation
        base_points = max_weight * 70.0  # Base scale out of 70
        raw_score = (base_points * cross_factor * decay_factor) + enrichment_boost

        # Clamping
        final_score = round(max(0.0, min(100.0, raw_score)), 1)

        # Categorical Tier assignment
        if final_score >= 85.0:
            tier = ConfidenceTier.CRITICAL
        elif final_score >= 70.0:
            tier = ConfidenceTier.HIGH
        elif final_score >= 40.0:
            tier = ConfidenceTier.MEDIUM
        else:
            tier = ConfidenceTier.LOW

        return ScoreBreakdown(
            source_weight=round(max_weight, 2),
            cross_source_factor=round(cross_factor, 2),
            decay_factor=round(decay_factor, 4),
            days_old=round(days_old, 2),
            enrichment_boost=round(enrichment_boost, 1),
            raw_calculated_score=round(raw_score, 1),
            final_score=final_score,
            tier=tier,
            is_whitelisted=False,
            whitelist_reason=None,
        )


# Global singleton instance
global_scoring_engine = ScoringEngine()
