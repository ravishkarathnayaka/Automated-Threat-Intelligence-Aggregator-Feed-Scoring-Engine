"""Multi-source consensus threshold and quorum evaluation for high-confidence blocking."""

from typing import Any, Dict, List, Set


class ConsensusScorer:
    """Evaluates whether an IoC meets multi-source quorum requirements for automated firewall blocking."""

    # Categorization of known threat feeds to ensure cross-domain corroboration
    SOURCE_DOMAINS: Dict[str, str] = {
        "abuseipdb": "reputation",
        "blocklist_de": "reputation",
        "urlhaus": "malware_distribution",
        "openphish": "phishing",
        "threatfox": "c2_infrastructure",
        "feodo_tracker": "botnet",
        "cisa_kev": "vulnerability_exploit",
        "alienvault_otx": "community_crowdsourced",
        "virustotal": "antivirus_telemetry",
    }

    @classmethod
    def evaluate(
        cls,
        sources: List[str],
        base_score: float,
        min_sources: int = 2,
        require_cross_domain: bool = False,
    ) -> Dict[str, Any]:
        """Evaluate consensus quorum and determine automated enforcement readiness."""
        clean_sources = list({s.strip().lower() for s in sources if s and s.strip()})
        source_count = len(clean_sources)

        domains: Set[str] = {
            cls.SOURCE_DOMAINS.get(s, "other") for s in clean_sources
        }

        # Check quorum conditions
        meets_count = source_count >= min_sources
        meets_domain = (len(domains) >= 2) if require_cross_domain else True

        quorum_reached = meets_count and meets_domain

        if quorum_reached:
            # Multi-source bonus
            bonus = min(15.0, (source_count - 1) * 5.0)
            final_score = min(100.0, base_score + bonus)
            enforcement_action = "auto_block" if final_score >= 70.0 else "monitor"
        else:
            # Single-source caution: cap at 65.0 to prevent false-positive blocks
            final_score = min(base_score, 65.0)
            enforcement_action = "quarantine_review"

        return {
            "consensus_reached": quorum_reached,
            "source_count": source_count,
            "sources": clean_sources,
            "distinct_domains": list(domains),
            "original_score": base_score,
            "consensus_adjusted_score": round(final_score, 1),
            "enforcement_action": enforcement_action,
            "actionable_for_blocklist": quorum_reached and (final_score >= 70.0),
        }
