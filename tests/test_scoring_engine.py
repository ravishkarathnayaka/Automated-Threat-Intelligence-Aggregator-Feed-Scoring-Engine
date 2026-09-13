"""Unit tests verifying confidence scoring mathematics, cross-source confirmation, and decay."""

from datetime import datetime, timedelta, timezone

from cti_core.models.indicator import ConfidenceTier
from cti_core.scoring.scoring_engine import ScoringEngine


def test_cross_feed_confirmation_boost():
    """Verify indicators confirmed across multiple feeds receive higher confidence scores."""
    engine = ScoringEngine()
    now = datetime.now(timezone.utc)

    # Single source report
    single_source = [{"source_name": "abuseipdb", "source_weight": 0.85}]
    score_single = engine.calculate_score("ipv4", "194.26.29.112", single_source, last_seen=now)

    # Multi-source confirmed (AbuseIPDB + URLhaus + OTX)
    multi_source = [
        {"source_name": "abuseipdb", "source_weight": 0.85},
        {"source_name": "urlhaus", "source_weight": 0.85},
        {"source_name": "otx", "source_weight": 0.75},
    ]
    score_multi = engine.calculate_score("ipv4", "194.26.29.112", multi_source, last_seen=now)

    assert score_multi.final_score > score_single.final_score
    assert score_multi.cross_source_factor == 1.45
    assert score_single.cross_source_factor == 1.00
    assert score_multi.tier in (ConfidenceTier.HIGH, ConfidenceTier.CRITICAL)


def test_time_decay():
    """Verify that older indicators decay in score over time."""
    engine = ScoringEngine()
    now = datetime.now(timezone.utc)
    ten_days_ago = now - timedelta(days=10)

    sources = [{"source_name": "abuseipdb", "source_weight": 0.85}]

    fresh_result = engine.calculate_score("ipv4", "194.26.29.112", sources, last_seen=now)
    aged_result = engine.calculate_score("ipv4", "194.26.29.112", sources, last_seen=ten_days_ago)

    assert aged_result.final_score < fresh_result.final_score
    assert aged_result.decay_factor < 0.65  # 0.95^10 ~ 0.5987


def test_authoritative_cisa_kev_score():
    """Verify CISA KEV authoritative weight produces high confidence score."""
    engine = ScoringEngine()
    now = datetime.now(timezone.utc)
    cisa_source = [{"source_name": "cisa_kev", "source_weight": 1.00}]

    result = engine.calculate_score("cve", "CVE-2021-44228", cisa_source, last_seen=now)
    assert result.source_weight == 1.00
    assert result.final_score >= 70.0


def test_enrichment_boost():
    """Verify that positive VirusTotal / OTX detections increase final score."""
    engine = ScoringEngine()
    now = datetime.now(timezone.utc)
    sources = [{"source_name": "abuseipdb", "source_weight": 0.85}]

    without_enrichment = engine.calculate_score("ipv4", "185.220.101.5", sources, last_seen=now)
    with_enrichment = engine.calculate_score(
        "ipv4",
        "185.220.101.5",
        sources,
        last_seen=now,
        enrichment_data={
            "virustotal": {"malicious_count": 45},
            "otx": {"pulse_count": 10},
        },
    )

    assert with_enrichment.enrichment_boost == 18.0  # 10 (VT) + 8 (OTX)
    assert with_enrichment.final_score > without_enrichment.final_score


def test_whitelist_hard_override_to_zero():
    """Verify whitelisted indicators always evaluate to 0 regardless of reporting sources."""
    engine = ScoringEngine()
    now = datetime.now(timezone.utc)
    high_threat_sources = [
        {"source_name": "cisa_kev", "source_weight": 1.00},
        {"source_name": "abuseipdb", "source_weight": 0.85},
        {"source_name": "urlhaus", "source_weight": 0.85},
    ]

    # Google DNS
    result = engine.calculate_score("ipv4", "8.8.8.8", high_threat_sources, last_seen=now)
    assert result.final_score == 0.0
    assert result.is_whitelisted is True
    assert result.tier == ConfidenceTier.LOW
    assert "Google" in (result.whitelist_reason or "")
